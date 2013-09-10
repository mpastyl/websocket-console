# Copyright 2011-2012 GRNET S.A. All rights reserved.
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

from django.core.urlresolvers import reverse
from django.utils.translation import ugettext as _
from django.utils.http import urlencode
from django.contrib.auth import authenticate
from django.http import (
    HttpResponse, HttpResponseBadRequest, HttpResponseForbidden)
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_http_methods

from urlparse import urlunsplit, urlsplit, parse_qsl

from astakos.im.util import restrict_next
from astakos.im.functions import login as auth_login, logout
from astakos.im.views.decorators import cookie_fix

import astakos.im.messages as astakos_messages
from astakos.im.settings import REDIRECT_ALLOWED_SCHEMES

import logging

logger = logging.getLogger(__name__)


@require_http_methods(["GET"])
@cookie_fix
def login(request):
    """
    If there is no ``next`` request parameter redirects to astakos index page
    displaying an error message.
    If the request user is authenticated and has signed the approval terms,
    redirects to `next` request parameter. If not, redirects to approval terms
    in order to return back here after agreeing with the terms.
    Otherwise, redirects to login in order to return back here after successful
    login.
    """
    next = request.GET.get('next')
    if not next:
        next = reverse('index')

    if not restrict_next(next, allowed_schemes=REDIRECT_ALLOWED_SCHEMES):
        return HttpResponseForbidden(_(
            astakos_messages.NOT_ALLOWED_NEXT_PARAM))
    force = request.GET.get('force', None)
    response = HttpResponse()
    if force == '' and request.user.is_authenticated():
        logout(request)

    if request.user.is_authenticated():
        # if user has not signed the approval terms
        # redirect to approval terms with next the request path
        if not request.user.signed_terms:
            # first build next parameter
            parts = list(urlsplit(request.build_absolute_uri()))
            params = dict(parse_qsl(parts[3], keep_blank_values=True))
            parts[3] = urlencode(params)
            next = urlunsplit(parts)

            # build url location
            parts[2] = reverse('latest_terms')
            params = {'next': next}
            parts[3] = urlencode(params)
            url = urlunsplit(parts)
            response['Location'] = url
            response.status_code = 302
            return response
        renew = request.GET.get('renew', None)
        if renew == '':
            request.user.renew_token(
                flush_sessions=True,
                current_key=request.session.session_key
            )
            try:
                request.user.save()
            except ValidationError, e:
                return HttpResponseBadRequest(e)
            # authenticate before login
            user = authenticate(
                username=request.user.username,
                auth_token=request.user.auth_token
            )
            auth_login(request, user)
            logger.info('Token reset for %s' % user.username)
        parts = list(urlsplit(next))
        parts[3] = urlencode({
            'uuid': request.user.uuid,
            'token': request.user.auth_token
        })
        url = urlunsplit(parts)
        response['Location'] = url
        response.status_code = 302
        return response
    else:
        # redirect to login with next the request path

        # first build next parameter
        parts = list(urlsplit(request.build_absolute_uri()))
        params = dict(parse_qsl(parts[3], keep_blank_values=True))
        # delete force parameter
        if 'force' in params:
            del params['force']
        parts[3] = urlencode(params)
        next = urlunsplit(parts)

        # build url location
        parts[2] = reverse('login')
        params = {'next': next}
        parts[3] = urlencode(params)
        url = urlunsplit(parts)
        response['Location'] = url
        response.status_code = 302
        return response
