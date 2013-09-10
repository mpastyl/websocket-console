# Copyright 2012, 2013 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

from datetime import datetime
from django.db.models import F
from astakos.quotaholder_app.exception import (
    QuotaholderError,
    NoCommissionError,
    CorruptedError, InvalidDataError,
    NoHoldingError,
    DuplicateError)

from astakos.quotaholder_app.commission import (
    Import, Release, Operations, finalize, undo)

from astakos.quotaholder_app.models import (
    Holding, Commission, Provision, ProvisionLog)


def format_datetime(d):
    return d.strftime('%Y-%m-%dT%H:%M:%S.%f')[:24]


def get_quota(holders=None, sources=None, resources=None):
    holdings = Holding.objects.all()

    if holders is not None:
        holdings = holdings.filter(holder__in=holders)

    if sources is not None:
        holdings = holdings.filter(source__in=sources)

    if resources is not None:
        holdings = holdings.filter(resource__in=resources)

    quotas = {}
    for holding in holdings:
        key = (holding.holder, holding.source, holding.resource)
        value = (holding.limit, holding.usage_min, holding.usage_max)
        quotas[key] = value

    return quotas


def _get_holdings_for_update(holding_keys):
    holders = set(holder for (holder, source, resource) in holding_keys)
    objs = Holding.objects
    hs = objs.filter(holder__in=holders).order_by('pk').select_for_update()

    holdings = {}
    for h in hs:
        key = h.holder, h.source, h.resource
        holdings[key] = h

    return holdings


def _mkProvision(key, quantity):
    holder, source, resource = key
    return {'holder': holder,
            'source': source,
            'resource': resource,
            'quantity': quantity,
            }


def set_quota(quotas):
    holding_keys = [key for (key, limit) in quotas]
    holdings = _get_holdings_for_update(holding_keys)

    for key, limit in quotas:
        try:
            h = holdings[key]
        except KeyError:
            holder, source, resource = key
            h = Holding(holder=holder,
                        source=source,
                        resource=resource)
        h.limit = limit
        h.save()
        holdings[key] = h


def add_resource_limit(holders=None, sources=None, resources=None, diff=0):
    holdings = Holding.objects.all()

    if holders is not None:
        holdings = holdings.filter(holder__in=holders)

    if sources is not None:
        holdings = holdings.filter(source__in=sources)

    if resources is not None:
        holdings = holdings.filter(resource__in=resources)

    holdings.update(limit=F('limit')+diff)


def issue_commission(clientkey, provisions, name="", force=False):
    operations = Operations()
    provisions_to_create = []

    keys = [key for (key, value) in provisions]
    holdings = _get_holdings_for_update(keys)
    try:
        checked = []
        for key, quantity in provisions:
            if not isinstance(quantity, (int, long)):
                raise InvalidDataError("Malformed provision")

            if key in checked:
                m = "Duplicate provision for %s" % str(key)
                provision = _mkProvision(key, quantity)
                raise DuplicateError(m,
                                     provision=provision)
            checked.append(key)

            # Target
            try:
                th = holdings[key]
            except KeyError:
                m = ("There is no such holding %s" % str(key))
                provision = _mkProvision(key, quantity)
                raise NoHoldingError(m,
                                     provision=provision)

            if quantity >= 0:
                operations.prepare(Import, th, quantity, force)

            else:  # release
                abs_quantity = -quantity
                operations.prepare(Release, th, abs_quantity, False)

            holdings[key] = th
            provisions_to_create.append((key, quantity))

    except QuotaholderError:
        operations.revert()
        raise

    commission = Commission.objects.create(clientkey=clientkey,
                                           name=name,
                                           issue_datetime=datetime.now())
    for (holder, source, resource), quantity in provisions_to_create:
        Provision.objects.create(serial=commission,
                                 holder=holder,
                                 source=source,
                                 resource=resource,
                                 quantity=quantity)

    return commission.serial


def _log_provision(commission, provision, holding, log_datetime, reason):

    kwargs = {
        'serial':              commission.serial,
        'name':                commission.name,
        'holder':              holding.holder,
        'source':              holding.source,
        'resource':            holding.resource,
        'limit':               holding.limit,
        'usage_min':           holding.usage_min,
        'usage_max':           holding.usage_max,
        'delta_quantity':      provision.quantity,
        'issue_time':          format_datetime(commission.issue_datetime),
        'log_time':            format_datetime(log_datetime),
        'reason':              reason,
    }

    ProvisionLog.objects.create(**kwargs)


def _get_commissions_for_update(clientkey, serials):
    cs = Commission.objects.filter(
        clientkey=clientkey, serial__in=serials).select_for_update()

    commissions = {}
    for c in cs:
        commissions[c.serial] = c
    return commissions


def _partition_by(f, l):
    d = {}
    for x in l:
        group = f(x)
        group_l = d.get(group, [])
        group_l.append(x)
        d[group] = group_l
    return d


def resolve_pending_commissions(clientkey, accept_set=None, reject_set=None,
                                reason=''):
    if accept_set is None:
        accept_set = []
    if reject_set is None:
        reject_set = []

    actions = dict.fromkeys(accept_set, True)
    conflicting = set()
    for serial in reject_set:
        if actions.get(serial) is True:
            actions.pop(serial)
            conflicting.add(serial)
        else:
            actions[serial] = False

    conflicting = list(conflicting)
    serials = actions.keys()
    commissions = _get_commissions_for_update(clientkey, serials)
    ps = Provision.objects.filter(serial__in=serials).select_for_update()
    holding_keys = sorted(p.holding_key() for p in ps)
    holdings = _get_holdings_for_update(holding_keys)
    provisions = _partition_by(lambda p: p.serial_id, ps)

    log_datetime = datetime.now()

    accepted, rejected, notFound = [], [], []
    for serial, accept in actions.iteritems():
        commission = commissions.get(serial)
        if commission is None:
            notFound.append(serial)
            continue

        accepted.append(serial) if accept else rejected.append(serial)

        ps = provisions.get(serial, [])
        for pv in ps:
            key = pv.holding_key()
            h = holdings.get(key)
            if h is None:
                raise CorruptedError("Corrupted provision")

            quantity = pv.quantity
            action = finalize if accept else undo
            if quantity >= 0:
                action(Import, h, quantity)
            else:  # release
                action(Release, h, -quantity)

            prefix = 'ACCEPT:' if accept else 'REJECT:'
            comm_reason = prefix + reason[-121:]
            _log_provision(commission, pv, h, log_datetime, comm_reason)
            pv.delete()
        commission.delete()
    return accepted, rejected, notFound, conflicting


def resolve_pending_commission(clientkey, serial, accept=True):
    if accept:
        ok, notOk, notF, confl = resolve_pending_commissions(
            clientkey=clientkey, accept_set=[serial])
    else:
        notOk, ok, notF, confl = resolve_pending_commissions(
            clientkey=clientkey, reject_set=[serial])

    assert notOk == confl == []
    assert ok + notF == [serial]
    return bool(ok)


def get_pending_commissions(clientkey):
    pending = Commission.objects.filter(clientkey=clientkey)
    pending_list = pending.values_list('serial', flat=True)
    return list(pending_list)


def get_commission(clientkey, serial):
    try:
        commission = Commission.objects.get(clientkey=clientkey,
                                            serial=serial)
    except Commission.DoesNotExist:
        raise NoCommissionError(serial)

    objs = Provision.objects
    provisions = objs.filter(serial=commission)

    ps = [p.todict() for p in provisions]

    response = {'serial':     serial,
                'provisions': ps,
                'issue_time': commission.issue_datetime,
                'name':       commission.name,
                }
    return response
