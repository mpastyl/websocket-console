# Copyright 2011 GRNET S.A. All rights reserved.
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

from astakos.im import settings
from astakos.im import presentation
from astakos.im.views import get_menu
from astakos.im.util import get_query
from astakos.im.auth_providers import PROVIDERS as AUTH_PROVIDERS

from django.utils import simplejson as json

GLOBAL_MESSAGES = settings.GLOBAL_MESSAGES
SIGNUP_MESSAGES = settings.SIGNUP_MESSAGES
LOGIN_MESSAGES = settings.LOGIN_MESSAGES
PROFILE_MESSAGES = settings.PROFILE_MESSAGES
PROFILE_EXTRA_LINKS = settings.PROFILE_EXTRA_LINKS


def im_modules(request):
    return {'im_modules': settings.IM_MODULES}

def auth_providers(request):
    active_auth_providers = []
    for module in settings.IM_MODULES:
        provider = AUTH_PROVIDERS.get(module, None)
        if provider:
            active_auth_providers.append(provider(request.user))

    return {'auth_providers': active_auth_providers,
            'master_auth_provider': active_auth_providers[0]}

def next(request):
    return {'next': get_query(request).get('next', '')}


def code(request):
    return {'code': request.GET.get('code', '')}

def last_login_method(request):
    return {'last_login_method': request.COOKIES.get('astakos_last_login_method', None)}

def invitations(request):
    return {'invitations_enabled': settings.INVITATIONS_ENABLED}


def media(request):
    return {'IM_STATIC_URL': settings.IM_STATIC_URL}


def custom_messages(request):
    global GLOBAL_MESSAGES, SIGNUP_MESSAGES, LOGIN_MESSAGES, PROFILE_MESSAGES

    # keep backwards compatibility with dict settings
    if type(GLOBAL_MESSAGES) == dict:
        GLOBAL_MESSAGES = GLOBAL_MESSAGES.items()
    if type(SIGNUP_MESSAGES) == dict:
        SIGNUP_MESSAGES = SIGNUP_MESSAGES.items()
    if type(LOGIN_MESSAGES) == dict:
        LOGIN_MESSAGES = LOGIN_MESSAGES.items()
    if type(PROFILE_MESSAGES) == dict:
        PROFILE_MESSAGES = PROFILE_MESSAGES.items()

    EXTRA_MESSAGES_SET = bool(GLOBAL_MESSAGES or SIGNUP_MESSAGES or
                              LOGIN_MESSAGES or PROFILE_MESSAGES)

    return {
        'GLOBAL_MESSAGES': GLOBAL_MESSAGES,
        'SIGNUP_MESSAGES': SIGNUP_MESSAGES,
        'LOGIN_MESSAGES': LOGIN_MESSAGES,
        'PROFILE_MESSAGES': PROFILE_MESSAGES,
        'PROFILE_EXTRA_LINKS': PROFILE_EXTRA_LINKS,
        'EXTRA_MESSAGES_SET': EXTRA_MESSAGES_SET
    }


def menu(request):
    try:
        resp = get_menu(request, True, False)
        menu_items = json.loads(resp.content)[1:]
    except Exception, e:
        return {}
    else:
        return {'menu': menu_items}

def membership_policies(request):
    return {'join_policies': presentation.PROJECT_MEMBER_JOIN_POLICIES,
            'leave_policies': presentation.PROJECT_MEMBER_LEAVE_POLICIES}

