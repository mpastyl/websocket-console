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

from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib import messages
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.urlresolvers import reverse

import django.contrib.auth.views as django_auth_views

from astakos.im.util import prepare_response, get_query
from astakos.im.models import PendingThirdPartyUser
from astakos.im.forms import LoginForm, ExtendedPasswordChangeForm, \
                             ExtendedSetPasswordForm
from astakos.im import settings
import astakos.im.messages as astakos_messages
from astakos.im import auth_providers as auth
from astakos.im.views.decorators import cookie_fix, requires_anonymous, \
    signed_terms_required, requires_auth_provider, login_required

from ratelimit.decorators import ratelimit

retries = settings.RATELIMIT_RETRIES_ALLOWED - 1
rate = str(retries) + '/m'


@requires_auth_provider('local')
@require_http_methods(["GET", "POST"])
@csrf_exempt
@requires_anonymous
@cookie_fix
@ratelimit(field='username', method='POST', rate=rate)
def login(request, on_failure='im/login.html'):
    """
    on_failure: the template name to render on login failure
    """
    if request.method == 'GET':
        return HttpResponseRedirect(reverse('login'))

    was_limited = getattr(request, 'limited', False)
    form = LoginForm(data=request.POST,
                     was_limited=was_limited,
                     request=request)
    next = get_query(request).get('next', '')
    third_party_token = get_query(request).get('key', False)
    provider = auth.get_provider('local')

    if not form.is_valid():
        if third_party_token:
            messages.info(request, provider.get_login_to_add_msg)

        return render_to_response(
            on_failure,
            {'login_form':form,
             'next':next,
             'key': third_party_token},
            context_instance=RequestContext(request))

    # get the user from the cache
    user = form.user_cache
    provider = auth.get_provider('local', user)

    if not provider.get_login_policy:
        message = provider.get_login_disabled_msg
        messages.error(request, message)
        return HttpResponseRedirect(reverse('login'))

    message = None
    if not user:
        message = provider.get_authentication_failed_msg
    elif not user.is_active:
        message = user.get_inactive_message('local')

    elif not user.has_auth_provider('local'):
        # valid user logged in with no auth providers set, add local provider
        # and let him log in
        if not user.get_available_auth_providers():
            user.add_auth_provider('local')
        else:
            message = _(astakos_messages.NO_LOCAL_AUTH)

    if message:
        messages.error(request, message)
        return render_to_response(on_failure,
                                  {'login_form': form},
                                  context_instance=RequestContext(request))

    response = prepare_response(request, user, next)
    if third_party_token:
        # use requests to assign the account he just authenticated with with
        # a third party provider account
        try:
            request.user.add_pending_auth_provider(third_party_token)
        except PendingThirdPartyUser.DoesNotExist:
            provider = auth.get_provider('local', request.user)
            messages.error(request, provider.get_add_failed_msg)

    provider = user.get_auth_provider('local')
    messages.success(request, provider.get_login_success_msg)
    response.set_cookie('astakos_last_login_method', 'local')
    return response


@require_http_methods(["GET"])
@cookie_fix
def password_reset_done(request, *args, **kwargs):
    messages.success(request, _(astakos_messages.PASSWORD_RESET_DONE))
    return HttpResponseRedirect(reverse('index'))


@require_http_methods(["GET"])
@cookie_fix
def password_reset_confirm_done(request, *args, **kwargs):
    messages.success(request, _(astakos_messages.PASSWORD_RESET_CONFIRM_DONE))
    return HttpResponseRedirect(reverse('index'))


@cookie_fix
def password_reset(request, *args, **kwargs):
    kwargs['post_reset_redirect'] = reverse(
            'astakos.im.views.target.local.password_reset_done')
    return django_auth_views.password_reset(request, *args, **kwargs)


@cookie_fix
def password_reset_confirm(request, *args, **kwargs):
    kwargs['post_reset_redirect'] = reverse(
            'astakos.im.views.target.local.password_reset_complete')
    return django_auth_views.password_reset_confirm(request, *args, **kwargs)


@cookie_fix
def password_reset_complete(request, *args, **kwargs):
    return django_auth_views.password_reset_complete(request, *args, **kwargs)


@require_http_methods(["GET", "POST"])
@signed_terms_required
@login_required
@cookie_fix
@requires_auth_provider('local', login=True)
def password_change(request, template_name='registration/password_change_form.html',
                    post_change_redirect=None, password_change_form=ExtendedPasswordChangeForm):

    create_password = False

    provider = auth.get_provider('local', request.user)

    # no local backend user wants to create a password
    if not request.user.has_auth_provider('local'):
        if not provider.get_add_policy:
            messages.error(request, provider.get_add_disabled_msg)
            return HttpResponseRedirect(reverse('edit_profile'))

        create_password = True
        password_change_form = ExtendedSetPasswordForm

    if post_change_redirect is None:
        post_change_redirect = reverse('edit_profile')

    if request.method == "POST":
        form_kwargs = dict(
            user=request.user,
            data=request.POST,
        )
        if not create_password:
            form_kwargs['session_key'] = request.session.session_key

        form = password_change_form(**form_kwargs)
        if form.is_valid():
            form.save()
            if create_password:
                provider = auth.get_provider('local', request.user)
                messages.success(request, provider.get_added_msg)
            else:
                messages.success(request,
                                 astakos_messages.PASSWORD_RESET_CONFIRM_DONE)
            return HttpResponseRedirect(post_change_redirect)
    else:
        form = password_change_form(user=request.user)
    return render_to_response(template_name, {
        'form': form,
    }, context_instance=RequestContext(request, {'create_password':
                                                 create_password}))

