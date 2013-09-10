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
from random import random
from datetime import datetime

from django import forms
from django.utils.translation import ugettext as _
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, \
    PasswordResetForm, PasswordChangeForm, SetPasswordForm
from django.core.mail import send_mail, get_connection
from django.contrib.auth.tokens import default_token_generator
from django.core.urlresolvers import reverse
from django.utils.safestring import mark_safe
from django.utils.encoding import smart_str
from django.db import transaction
from django.core import validators
from django.core.exceptions import PermissionDenied

from synnefo_branding.utils import render_to_string
from synnefo.lib import join_urls
from astakos.im.models import AstakosUser, EmailChange, Invitation, Resource, \
    PendingThirdPartyUser, get_latest_terms, ProjectApplication, Project
from astakos.im import presentation
from astakos.im.widgets import DummyWidget, RecaptchaWidget
from astakos.im.functions import send_change_email, submit_application, \
    accept_membership_checks

from astakos.im.util import reserved_verified_email, model_to_dict
from astakos.im import auth_providers
from astakos.im import settings

import astakos.im.messages as astakos_messages

import logging
import hashlib
import recaptcha.client.captcha as captcha
import re

logger = logging.getLogger(__name__)

DOMAIN_VALUE_REGEX = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$',
    re.IGNORECASE)


class StoreUserMixin(object):

    def store_user(self, user, request=None):
        """
        WARNING: this should be wrapped inside a transactional view/method.
        """
        user.save()
        self.post_store_user(user, request)
        return user

    def post_store_user(self, user, request):
        """
        Interface method for descendant backends to be able to do stuff within
        the transaction enabled by store_user.
        """
        pass


class LocalUserCreationForm(UserCreationForm, StoreUserMixin):
    """
    Extends the built in UserCreationForm in several ways:

    * Adds email, first_name, last_name, recaptcha_challenge_field,
    * recaptcha_response_field field.
    * The username field isn't visible and it is assigned a generated id.
    * User created is not active.
    """
    recaptcha_challenge_field = forms.CharField(widget=DummyWidget)
    recaptcha_response_field = forms.CharField(
        widget=RecaptchaWidget, label='')

    class Meta:
        model = AstakosUser
        fields = ("email", "first_name", "last_name",
                  "has_signed_terms", "has_signed_terms")

    def __init__(self, *args, **kwargs):
        """
        Changes the order of fields, and removes the username field.
        """
        request = kwargs.pop('request', None)
        provider = kwargs.pop('provider', 'local')

        # we only use LocalUserCreationForm for local provider
        if not provider == 'local':
            raise Exception('Invalid provider')

        self.ip = None
        if request:
            self.ip = request.META.get('REMOTE_ADDR',
                                       request.META.get('HTTP_X_REAL_IP',
                                                        None))

        super(LocalUserCreationForm, self).__init__(*args, **kwargs)
        self.fields.keyOrder = ['email', 'first_name', 'last_name',
                                'password1', 'password2']

        if settings.RECAPTCHA_ENABLED:
            self.fields.keyOrder.extend(['recaptcha_challenge_field',
                                         'recaptcha_response_field', ])
        if get_latest_terms():
            self.fields.keyOrder.append('has_signed_terms')

        if 'has_signed_terms' in self.fields:
            # Overriding field label since we need to apply a link
            # to the terms within the label
            terms_link_html = '<a href="%s" target="_blank">%s</a>' \
                % (reverse('latest_terms'), _("the terms"))
            self.fields['has_signed_terms'].label = \
                mark_safe("I agree with %s" % terms_link_html)

    def clean_email(self):
        email = self.cleaned_data['email']
        if not email:
            raise forms.ValidationError(_(astakos_messages.REQUIRED_FIELD))
        if reserved_verified_email(email):
            raise forms.ValidationError(_(astakos_messages.EMAIL_USED))
        return email

    def clean_has_signed_terms(self):
        has_signed_terms = self.cleaned_data['has_signed_terms']
        if not has_signed_terms:
            raise forms.ValidationError(_(astakos_messages.SIGN_TERMS))
        return has_signed_terms

    def clean_recaptcha_response_field(self):
        if 'recaptcha_challenge_field' in self.cleaned_data:
            self.validate_captcha()
        return self.cleaned_data['recaptcha_response_field']

    def clean_recaptcha_challenge_field(self):
        if 'recaptcha_response_field' in self.cleaned_data:
            self.validate_captcha()
        return self.cleaned_data['recaptcha_challenge_field']

    def validate_captcha(self):
        rcf = self.cleaned_data['recaptcha_challenge_field']
        rrf = self.cleaned_data['recaptcha_response_field']
        check = captcha.submit(
            rcf, rrf, settings.RECAPTCHA_PRIVATE_KEY, self.ip)
        if not check.is_valid:
            raise forms.ValidationError(_(
                astakos_messages.CAPTCHA_VALIDATION_ERR))

    def post_store_user(self, user, request=None):
        """
        Interface method for descendant backends to be able to do stuff within
        the transaction enabled by store_user.
        """
        user.add_auth_provider('local', auth_backend='astakos')
        user.set_password(self.cleaned_data['password1'])

    def save(self, commit=True):
        """
        Saves the email, first_name and last_name properties, after the normal
        save behavior is complete.
        """
        user = super(LocalUserCreationForm, self).save(commit=False)
        user.date_signed_terms = datetime.now()
        user.renew_token()
        if commit:
            user.save()
            logger.info('Created user %s', user.log_display)
        return user


class InvitedLocalUserCreationForm(LocalUserCreationForm):
    """
    Extends the LocalUserCreationForm: email is readonly.
    """
    class Meta:
        model = AstakosUser
        fields = ("email", "first_name", "last_name", "has_signed_terms")

    def __init__(self, *args, **kwargs):
        """
        Changes the order of fields, and removes the username field.
        """
        super(InvitedLocalUserCreationForm, self).__init__(*args, **kwargs)

        #set readonly form fields
        ro = ('email', 'username',)
        for f in ro:
            self.fields[f].widget.attrs['readonly'] = True

    def save(self, commit=True):
        user = super(InvitedLocalUserCreationForm, self).save(commit=False)
        user.set_invitations_level()
        user.email_verified = True
        if commit:
            user.save()
        return user


class ThirdPartyUserCreationForm(forms.ModelForm, StoreUserMixin):
    email = forms.EmailField(
        label='Contact email',
        help_text='This is needed for contact purposes. '
        'It doesn&#39;t need to be the same with the one you '
        'provided to login previously. '
    )

    class Meta:
        model = AstakosUser
        fields = ['email', 'first_name', 'last_name', 'has_signed_terms']

    def __init__(self, *args, **kwargs):
        """
        Changes the order of fields, and removes the username field.
        """

        self.provider = kwargs.pop('provider', None)
        self.request = kwargs.pop('request', None)
        if not self.provider or self.provider == 'local':
            raise Exception('Invalid provider, %r' % self.provider)

        # ThirdPartyUserCreationForm should always get instantiated with
        # a third_party_token value
        self.third_party_token = kwargs.pop('third_party_token', None)
        if not self.third_party_token:
            raise Exception('ThirdPartyUserCreationForm'
                            ' requires third_party_token')

        super(ThirdPartyUserCreationForm, self).__init__(*args, **kwargs)

        if not get_latest_terms():
            del self.fields['has_signed_terms']

        if 'has_signed_terms' in self.fields:
            # Overriding field label since we need to apply a link
            # to the terms within the label
            terms_link_html = '<a href="%s" target="_blank">%s</a>' \
                % (reverse('latest_terms'), _("the terms"))
            self.fields['has_signed_terms'].label = \
                mark_safe("I agree with %s" % terms_link_html)

    def clean_email(self):
        email = self.cleaned_data['email']
        if not email:
            raise forms.ValidationError(_(astakos_messages.REQUIRED_FIELD))
        if reserved_verified_email(email):
            provider_id = self.provider
            provider = auth_providers.get_provider(provider_id)
            extra_message = provider.get_add_to_existing_account_msg

            raise forms.ValidationError(mark_safe(
                _(astakos_messages.EMAIL_USED) + ' ' + extra_message))
        return email

    def clean_has_signed_terms(self):
        has_signed_terms = self.cleaned_data['has_signed_terms']
        if not has_signed_terms:
            raise forms.ValidationError(_(astakos_messages.SIGN_TERMS))
        return has_signed_terms

    def _get_pending_user(self):
        return PendingThirdPartyUser.objects.get(token=self.third_party_token)

    def post_store_user(self, user, request=None):
        pending = self._get_pending_user()
        provider = pending.get_provider(user)
        provider.add_to_user()
        pending.delete()

    def save(self, commit=True):
        user = super(ThirdPartyUserCreationForm, self).save(commit=False)
        user.set_unusable_password()
        user.renew_token()
        user.date_signed_terms = datetime.now()
        if commit:
            user.save()
            logger.info('Created user %s' % user.log_display)
        return user


class InvitedThirdPartyUserCreationForm(ThirdPartyUserCreationForm):
    """
    Extends the ThirdPartyUserCreationForm: email is readonly.
    """
    def __init__(self, *args, **kwargs):
        """
        Changes the order of fields, and removes the username field.
        """
        super(
            InvitedThirdPartyUserCreationForm, self).__init__(*args, **kwargs)

        #set readonly form fields
        ro = ('email',)
        for f in ro:
            self.fields[f].widget.attrs['readonly'] = True

    def save(self, commit=True):
        user = super(InvitedThirdPartyUserCreationForm, self).save(commit=False)
        user.set_invitation_level()
        user.email_verified = True
        if commit:
            user.save()
        return user


class ShibbolethUserCreationForm(ThirdPartyUserCreationForm):
    additional_email = forms.CharField(
        widget=forms.HiddenInput(), label='', required=False)

    def __init__(self, *args, **kwargs):
        super(ShibbolethUserCreationForm, self).__init__(*args, **kwargs)
        # copy email value to additional_mail in case user will change it
        name = 'email'
        field = self.fields[name]
        self.initial['additional_email'] = self.initial.get(name, field.initial)
        self.initial['email'] = None


class InvitedShibbolethUserCreationForm(ShibbolethUserCreationForm,
                                        InvitedThirdPartyUserCreationForm):
    pass


class LoginForm(AuthenticationForm):
    username = forms.EmailField(label=_("Email"))
    recaptcha_challenge_field = forms.CharField(widget=DummyWidget)
    recaptcha_response_field = forms.CharField(
        widget=RecaptchaWidget, label='')

    def __init__(self, *args, **kwargs):
        was_limited = kwargs.get('was_limited', False)
        request = kwargs.get('request', None)
        if request:
            self.ip = request.META.get('REMOTE_ADDR',
                                       request.META.get('HTTP_X_REAL_IP', None))

        t = ('request', 'was_limited')
        for elem in t:
            if elem in kwargs.keys():
                kwargs.pop(elem)
        super(LoginForm, self).__init__(*args, **kwargs)

        self.fields.keyOrder = ['username', 'password']
        if was_limited and settings.RECAPTCHA_ENABLED:
            self.fields.keyOrder.extend(['recaptcha_challenge_field',
                                         'recaptcha_response_field', ])

    def clean_username(self):
        return self.cleaned_data['username'].lower()

    def clean_recaptcha_response_field(self):
        if 'recaptcha_challenge_field' in self.cleaned_data:
            self.validate_captcha()
        return self.cleaned_data['recaptcha_response_field']

    def clean_recaptcha_challenge_field(self):
        if 'recaptcha_response_field' in self.cleaned_data:
            self.validate_captcha()
        return self.cleaned_data['recaptcha_challenge_field']

    def validate_captcha(self):
        rcf = self.cleaned_data['recaptcha_challenge_field']
        rrf = self.cleaned_data['recaptcha_response_field']
        check = captcha.submit(
            rcf, rrf, settings.RECAPTCHA_PRIVATE_KEY, self.ip)
        if not check.is_valid:
            raise forms.ValidationError(_(
                astakos_messages.CAPTCHA_VALIDATION_ERR))

    def clean(self):
        """
        Override default behavior in order to check user's activation later
        """
        username = self.cleaned_data.get('username')

        if username:
            try:
                user = AstakosUser.objects.get_by_identifier(username)
                if not user.has_auth_provider('local'):
                    provider = auth_providers.get_provider('local', user)
                    msg = provider.get_login_disabled_msg
                    raise forms.ValidationError(mark_safe(msg))
            except AstakosUser.DoesNotExist:
                pass

        try:
            super(LoginForm, self).clean()
        except forms.ValidationError, e:
            if self.user_cache is None:
                raise
            if not self.user_cache.is_active:
                msg = self.user_cache.get_inactive_message('local')
                raise forms.ValidationError(msg)
            if self.request:
                if not self.request.session.test_cookie_worked():
                    raise
        return self.cleaned_data


class ProfileForm(forms.ModelForm):
    """
    Subclass of ``ModelForm`` for permiting user to edit his/her profile.
    Most of the fields are readonly since the user is not allowed to change
    them.

    The class defines a save method which sets ``is_verified`` to True so as the
    user during the next login will not to be redirected to profile page.
    """
    email = forms.EmailField(label='E-mail address', help_text='E-mail address')
    renew = forms.BooleanField(label='Renew token', required=False)

    class Meta:
        model = AstakosUser
        fields = ('email', 'first_name', 'last_name')

    def __init__(self, *args, **kwargs):
        self.session_key = kwargs.pop('session_key', None)
        super(ProfileForm, self).__init__(*args, **kwargs)
        instance = getattr(self, 'instance', None)
        ro_fields = ('email',)
        if instance and instance.id:
            for field in ro_fields:
                self.fields[field].widget.attrs['readonly'] = True

    def clean_email(self):
        return self.instance.email

    def save(self, commit=True):
        user = super(ProfileForm, self).save(commit=False)
        user.is_verified = True
        if self.cleaned_data.get('renew'):
            user.renew_token(
                flush_sessions=True,
                current_key=self.session_key
            )
        if commit:
            user.save()
        return user



class FeedbackForm(forms.Form):
    """
    Form for writing feedback.
    """
    feedback_msg = forms.CharField(widget=forms.Textarea, label=u'Message')
    feedback_data = forms.CharField(widget=forms.HiddenInput(), label='',
                                    required=False)


class SendInvitationForm(forms.Form):
    """
    Form for sending an invitations
    """

    email = forms.EmailField(required=True, label='Email address')
    first_name = forms.EmailField(label='First name')
    last_name = forms.EmailField(label='Last name')


class ExtendedPasswordResetForm(PasswordResetForm):
    """
    Extends PasswordResetForm by overriding

    save method: to pass a custom from_email in send_mail.
    clean_email: to handle local auth provider checks
    """
    def clean_email(self):
        # we override the default django auth clean_email to provide more
        # detailed messages in case of inactive users
        email = self.cleaned_data['email']
        try:
            user = AstakosUser.objects.get_by_identifier(email)
            self.users_cache = [user]
            if not user.is_active:
                msg = mark_safe(user.get_inactive_message('local'))
                raise forms.ValidationError(msg)

            provider = auth_providers.get_provider('local', user)
            if not user.has_usable_password():
                msg = provider.get_unusable_password_msg
                raise forms.ValidationError(mark_safe(msg))

            if not user.can_change_password():
                msg = provider.get_cannot_change_password_msg
                raise forms.ValidationError(mark_safe(msg))

        except AstakosUser.DoesNotExist:
            raise forms.ValidationError(_(astakos_messages.EMAIL_UNKNOWN))
        return email

    def save(
        self, domain_override=None, email_template_name='registration/password_reset_email.html',
            use_https=False, token_generator=default_token_generator, request=None):
        """
        Generates a one-use only link for resetting password and sends to the user.
        """
        for user in self.users_cache:
            url = user.astakosuser.get_password_reset_url(token_generator)
            url = join_urls(settings.BASE_HOST, url)
            c = {
                'email': user.email,
                'url': url,
                'site_name': settings.SITENAME,
                'user': user,
                'baseurl': settings.BASE_URL,
                'support': settings.CONTACT_EMAIL
            }
            message = render_to_string(email_template_name, c)
            from_email = settings.SERVER_EMAIL
            send_mail(_(astakos_messages.PASSWORD_RESET_EMAIL_SUBJECT),
                      message,
                      from_email,
                      [user.email],
                      connection=get_connection())


class EmailChangeForm(forms.ModelForm):

    class Meta:
        model = EmailChange
        fields = ('new_email_address',)

    def clean_new_email_address(self):
        addr = self.cleaned_data['new_email_address']
        if reserved_verified_email(addr):
            raise forms.ValidationError(_(astakos_messages.EMAIL_USED))
        return addr

    def save(self, request, email_template_name='registration/email_change_email.txt', commit=True):
        ec = super(EmailChangeForm, self).save(commit=False)
        ec.user = request.user
        # delete pending email changes
        request.user.emailchanges.all().delete()

        activation_key = hashlib.sha1(
            str(random()) + smart_str(ec.new_email_address))
        ec.activation_key = activation_key.hexdigest()
        if commit:
            ec.save()
        send_change_email(ec, request, email_template_name=email_template_name)


class SignApprovalTermsForm(forms.ModelForm):

    class Meta:
        model = AstakosUser
        fields = ("has_signed_terms",)

    def __init__(self, *args, **kwargs):
        super(SignApprovalTermsForm, self).__init__(*args, **kwargs)

    def clean_has_signed_terms(self):
        has_signed_terms = self.cleaned_data['has_signed_terms']
        if not has_signed_terms:
            raise forms.ValidationError(_(astakos_messages.SIGN_TERMS))
        return has_signed_terms

    def save(self, commit=True):
        user = super(SignApprovalTermsForm, self).save(commit)
        user.date_signed_terms = datetime.now()
        if commit:
            user.save()
        return user


class InvitationForm(forms.ModelForm):

    username = forms.EmailField(label=_("Email"))

    def __init__(self, *args, **kwargs):
        super(InvitationForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Invitation
        fields = ('username', 'realname')

    def clean_username(self):
        username = self.cleaned_data['username']
        try:
            Invitation.objects.get(username=username)
            raise forms.ValidationError(_(astakos_messages.INVITATION_EMAIL_EXISTS))
        except Invitation.DoesNotExist:
            pass
        return username


class ExtendedPasswordChangeForm(PasswordChangeForm):
    """
    Extends PasswordChangeForm by enabling user
    to optionally renew also the token.
    """
    if not settings.NEWPASSWD_INVALIDATE_TOKEN:
        renew = forms.BooleanField(label='Renew token', required=False,
                                   initial=True,
                                   help_text='Unsetting this may result in security risk.')

    def __init__(self, user, *args, **kwargs):
        self.session_key = kwargs.pop('session_key', None)
        super(ExtendedPasswordChangeForm, self).__init__(user, *args, **kwargs)

    def save(self, commit=True):
        try:
            if settings.NEWPASSWD_INVALIDATE_TOKEN or \
                    self.cleaned_data.get('renew'):
                self.user.renew_token()
            self.user.flush_sessions(current_key=self.session_key)
        except AttributeError:
            # if user model does has not such methods
            pass
        return super(ExtendedPasswordChangeForm, self).save(commit=commit)

class ExtendedSetPasswordForm(SetPasswordForm):
    """
    Extends SetPasswordForm by enabling user
    to optionally renew also the token.
    """
    if not settings.NEWPASSWD_INVALIDATE_TOKEN:
        renew = forms.BooleanField(
            label='Renew token',
            required=False,
            initial=True,
            help_text='Unsetting this may result in security risk.')

    def __init__(self, user, *args, **kwargs):
        super(ExtendedSetPasswordForm, self).__init__(user, *args, **kwargs)

    @transaction.commit_on_success()
    def save(self, commit=True):
        try:
            self.user = AstakosUser.objects.get(id=self.user.id)
            if settings.NEWPASSWD_INVALIDATE_TOKEN or \
                    self.cleaned_data.get('renew'):
                self.user.renew_token()

            provider = auth_providers.get_provider('local', self.user)
            if provider.get_add_policy:
                provider.add_to_user()

        except BaseException, e:
            logger.exception(e)
        return super(ExtendedSetPasswordForm, self).save(commit=commit)




app_name_label       =  "Project name"
app_name_placeholder = _("myproject.mylab.ntua.gr")
app_name_validator   =  validators.RegexValidator(
                            DOMAIN_VALUE_REGEX,
                            _(astakos_messages.DOMAIN_VALUE_ERR),
                            'invalid')
app_name_help        =  _("""
        The project's name should be in a domain format.
        The domain shouldn't neccessarily exist in the real
        world but is helpful to imply a structure.
        e.g.: myproject.mylab.ntua.gr or
        myservice.myteam.myorganization""")
app_name_widget      =  forms.TextInput(
                            attrs={'placeholder': app_name_placeholder})


app_home_label       =  "Homepage URL"
app_home_placeholder =  'myinstitution.org/myproject/'
app_home_help        =  _("""
        URL pointing at your project's site.
        e.g.: myinstitution.org/myproject/.
        Leave blank if there is no website.""")
app_home_widget      =  forms.TextInput(
                            attrs={'placeholder': app_home_placeholder})

app_desc_label       =  _("Description")
app_desc_help        =  _("""
        Please provide a short but descriptive abstract of your
        project, so that anyone searching can quickly understand
        what this project is about.""")

app_comment_label    =  _("Comments for review (private)")
app_comment_help     =  _("""
        Write down any comments you may have for the reviewer
        of this application (e.g. background and rationale to
        support your request).
        The comments are strictly for the review process
        and will not be made public.""")

app_start_date_label =  _("Start date")
app_start_date_help  =  _("""
        Provide a date when your need your project to be created,
        and members to be able to join and get resources.
        This date is only a hint to help prioritize reviews.""")

app_end_date_label   =  _("Termination date")
app_end_date_help    =  _("""
        At this date, the project will be automatically terminated
        and its resource grants revoked from all members. If you are
        not certain, it is best to start with a conservative estimation.
        You can always re-apply for an extension, if you need.""")

join_policy_label    =  _("Joining policy")
app_member_join_policy_help    =  _("""
        Select how new members are accepted into the project.""")
leave_policy_label   =  _("Leaving policy")
app_member_leave_policy_help    =  _("""
        Select how new members can leave the project.""")

max_members_label    =  _("Maximum member count")
max_members_help     =  _("""
        Specify the maximum number of members this project may have,
        including the owner. Beyond this number, no new members
        may join the project and be granted the project resources.
        If you are not certain, it is best to start with a conservative
        limit. You can always request a raise when you need it.""")

join_policies = presentation.PROJECT_MEMBER_JOIN_POLICIES.items()
leave_policies = presentation.PROJECT_MEMBER_LEAVE_POLICIES.items()

class ProjectApplicationForm(forms.ModelForm):

    name = forms.CharField(
        label     = app_name_label,
        help_text = app_name_help,
        widget    = app_name_widget,
        validators = [app_name_validator])

    homepage = forms.URLField(
        label     = app_home_label,
        help_text = app_home_help,
        widget    = app_home_widget,
        required  = False)

    description = forms.CharField(
        label     = app_desc_label,
        help_text = app_desc_help,
        widget    = forms.Textarea,
        required  = False)

    comments = forms.CharField(
        label     = app_comment_label,
        help_text = app_comment_help,
        widget    = forms.Textarea,
        required  = False)

    start_date = forms.DateTimeField(
        label     = app_start_date_label,
        help_text = app_start_date_help,
        required  = False)

    end_date = forms.DateTimeField(
        label     = app_end_date_label,
        help_text = app_end_date_help)

    member_join_policy  = forms.TypedChoiceField(
        label     = join_policy_label,
        help_text = app_member_join_policy_help,
        initial   = 2,
        coerce    = int,
        choices   = join_policies)

    member_leave_policy = forms.TypedChoiceField(
        label     = leave_policy_label,
        help_text = app_member_leave_policy_help,
        coerce    = int,
        choices   = leave_policies)

    limit_on_members_number = forms.IntegerField(
        label     = max_members_label,
        help_text = max_members_help,
        min_value = 0,
        required  = False)

    class Meta:
        model = ProjectApplication
        fields = ( 'name', 'homepage', 'description',
                    'start_date', 'end_date', 'comments',
                    'member_join_policy', 'member_leave_policy',
                    'limit_on_members_number')

    def __init__(self, *args, **kwargs):
        instance = kwargs.get('instance')
        self.precursor_application = instance
        super(ProjectApplicationForm, self).__init__(*args, **kwargs)
        # in case of new application remove closed join policy
        if not instance:
            policies = presentation.PROJECT_MEMBER_JOIN_POLICIES.copy()
            policies.pop(3)
            self.fields['member_join_policy'].choices = policies.iteritems()

    def clean_start_date(self):
        start_date = self.cleaned_data.get('start_date')
        if not self.precursor_application:
            today = datetime.now()
            today = datetime(today.year, today.month, today.day)
            if start_date and (start_date - today).days < 0:
                raise forms.ValidationError(
                _(astakos_messages.INVALID_PROJECT_START_DATE))
        return start_date

    def clean_end_date(self):
        start_date = self.cleaned_data.get('start_date')
        end_date = self.cleaned_data.get('end_date')
        today = datetime.now()
        today = datetime(today.year, today.month, today.day)
        if end_date and (end_date - today).days < 0:
            raise forms.ValidationError(
                _(astakos_messages.INVALID_PROJECT_END_DATE))
        if start_date and (end_date - start_date).days <= 0:
            raise forms.ValidationError(
                _(astakos_messages.INCONSISTENT_PROJECT_DATES))
        return end_date

    def clean(self):
        userid = self.data.get('user', None)
        policies = self.resource_policies
        self.user = None
        if userid:
            try:
                self.user = AstakosUser.objects.get(id=userid)
            except AstakosUser.DoesNotExist:
                pass
        if not self.user:
            raise forms.ValidationError(_(astakos_messages.NO_APPLICANT))
        super(ProjectApplicationForm, self).clean()
        return self.cleaned_data

    @property
    def resource_policies(self):
        policies = []
        append = policies.append
        for name, value in self.data.iteritems():
            if not value:
                continue
            uplimit = value
            if name.endswith('_uplimit'):
                subs = name.split('_uplimit')
                prefix, suffix = subs
                try:
                    resource = Resource.objects.get(name=prefix)
                except Resource.DoesNotExist:
                    raise forms.ValidationError("Resource %s does not exist" %
                                                resource.name)
                # keep only resource limits for selected resource groups
                if self.data.get(
                    'is_selected_%s' % resource.group, "0"
                 ) == "1":
                    if not resource.allow_in_projects:
                        raise forms.ValidationError("Invalid resource %s" %
                                                    resource.name)
                    d = model_to_dict(resource)
                    if uplimit:
                        d.update(dict(resource=prefix, uplimit=uplimit))
                    else:
                        d.update(dict(resource=prefix, uplimit=None))
                    append(d)

        ordered_keys = presentation.RESOURCES['resources_order']
        def resource_order(r):
            if r['str_repr'] in ordered_keys:
                return ordered_keys.index(r['str_repr'])
            else:
                return -1

        policies = sorted(policies, key=resource_order)
        return policies

    def cleaned_resource_policies(self):
        return [(d['name'], d['uplimit']) for d in self.resource_policies]

    def save(self, commit=True):
        data = dict(self.cleaned_data)
        data['precursor_id'] = self.instance.id
        is_new = self.instance.id is None
        data['owner'] = self.user if is_new else self.instance.owner
        data['resource_policies'] = self.cleaned_resource_policies()
        data['request_user'] = self.user
        submit_application(**data)


class ProjectSortForm(forms.Form):
    sorting = forms.ChoiceField(
        label='Sort by',
        choices=(('name', 'Sort by Name'),
                 ('issue_date', 'Sort by Issue date'),
                 ('start_date', 'Sort by Start Date'),
                 ('end_date', 'Sort by End Date'),
#                  ('approved_members_num', 'Sort by Participants'),
                 ('state', 'Sort by Status'),
                 ('member_join_policy__description', 'Sort by Member Join Policy'),
                 ('member_leave_policy__description', 'Sort by Member Leave Policy'),
                 ('-name', 'Sort by Name'),
                 ('-issue_date', 'Sort by Issue date'),
                 ('-start_date', 'Sort by Start Date'),
                 ('-end_date', 'Sort by End Date'),
#                  ('-approved_members_num', 'Sort by Participants'),
                 ('-state', 'Sort by Status'),
                 ('-member_join_policy__description', 'Sort by Member Join Policy'),
                 ('-member_leave_policy__description', 'Sort by Member Leave Policy')
        ),
        required=True
    )

class AddProjectMembersForm(forms.Form):
    q = forms.CharField(
        widget=forms.Textarea(attrs={
            'placeholder': astakos_messages.ADD_PROJECT_MEMBERS_Q_PLACEHOLDER}
            ),
        label=_('Add members'),
        help_text=_(astakos_messages.ADD_PROJECT_MEMBERS_Q_HELP),
        required=True,)

    def __init__(self, *args, **kwargs):
        chain_id = kwargs.pop('chain_id', None)
        if chain_id:
            self.project = Project.objects.get(id=chain_id)
        self.request_user = kwargs.pop('request_user', None)
        super(AddProjectMembersForm, self).__init__(*args, **kwargs)

    def clean(self):
        try:
            accept_membership_checks(self.project, self.request_user)
        except PermissionDenied, e:
            raise forms.ValidationError(e)

        q = self.cleaned_data.get('q') or ''
        users = q.split(',')
        users = list(u.strip() for u in users if u)
        db_entries = AstakosUser.objects.verified().filter(email__in=users)
        unknown = list(set(users) - set(u.email for u in db_entries))
        if unknown:
            raise forms.ValidationError(
                _(astakos_messages.UNKNOWN_USERS) % ','.join(unknown))
        self.valid_users = db_entries
        return self.cleaned_data

    def get_valid_users(self):
        """Should be called after form cleaning"""
        try:
            return self.valid_users
        except:
            return ()

class ProjectMembersSortForm(forms.Form):
    sorting = forms.ChoiceField(
        label='Sort by',
        choices=(('person__email', 'User Id'),
                 ('person__first_name', 'Name'),
                 ('acceptance_date', 'Acceptance date')
        ),
        required=True
    )


class ProjectSearchForm(forms.Form):
    q = forms.CharField(max_length=200, label='Search project', required=False)


class ExtendedProfileForm(ProfileForm):
    """
    Profile form that combines `email change` and `password change` user
    actions by propagating submited data to internal EmailChangeForm
    and ExtendedPasswordChangeForm objects.
    """

    password_change_form = None
    email_change_form = None

    password_change = False
    email_change = False

    extra_forms_fields = {
        'email': ['new_email_address'],
        'password': ['old_password', 'new_password1', 'new_password2']
    }

    fields = ('email')
    change_password = forms.BooleanField(initial=False, required=False)
    change_email = forms.BooleanField(initial=False, required=False)

    email_changed = False
    password_changed = False

    def __init__(self, *args, **kwargs):
        session_key = kwargs.get('session_key', None)
        self.fields_list = [
                'email',
                'new_email_address',
                'first_name',
                'last_name',
                'old_password',
                'new_password1',
                'new_password2',
                'change_email',
                'change_password',
        ]

        super(ExtendedProfileForm, self).__init__(*args, **kwargs)
        self.session_key = session_key
        if self.instance.can_change_password():
            self.password_change = True
        else:
            self.fields_list.remove('old_password')
            self.fields_list.remove('new_password1')
            self.fields_list.remove('new_password2')
            self.fields_list.remove('change_password')
            del self.fields['change_password']

        if settings.EMAILCHANGE_ENABLED and self.instance.can_change_email():
            self.email_change = True
        else:
            self.fields_list.remove('new_email_address')
            self.fields_list.remove('change_email')
            del self.fields['change_email']

        self._init_extra_forms()
        self.save_extra_forms = []
        self.success_messages = []
        self.fields.keyOrder = self.fields_list


    def _init_extra_form_fields(self):
        if self.email_change:
            self.fields.update(self.email_change_form.fields)
            self.fields['new_email_address'].required = False
            self.fields['email'].help_text = _('Change the email associated with '
                                               'your account. This email will '
                                               'remain active until you verify '
                                               'your new one.')

        if self.password_change:
            self.fields.update(self.password_change_form.fields)
            self.fields['old_password'].required = False
            self.fields['old_password'].label = _('Password')
            self.fields['old_password'].help_text = _('Change your password.')
            self.fields['old_password'].initial = 'password'
            self.fields['new_password1'].required = False
            self.fields['new_password2'].required = False

    def _update_extra_form_errors(self):
        if self.cleaned_data.get('change_password'):
            self.errors.update(self.password_change_form.errors)
        if self.cleaned_data.get('change_email'):
            self.errors.update(self.email_change_form.errors)

    def _init_extra_forms(self):
        self.email_change_form = EmailChangeForm(self.data)
        self.password_change_form = ExtendedPasswordChangeForm(user=self.instance,
                                   data=self.data, session_key=self.session_key)
        self._init_extra_form_fields()

    def is_valid(self):
        password, email = True, True
        profile = super(ExtendedProfileForm, self).is_valid()
        if profile and self.cleaned_data.get('change_password', None):
            self.password_change_form.fields['new_password1'].required = True
            self.password_change_form.fields['new_password2'].required = True
            password = self.password_change_form.is_valid()
            self.save_extra_forms.append('password')
        if profile and self.cleaned_data.get('change_email'):
            self.fields['new_email_address'].required = True
            email = self.email_change_form.is_valid()
            self.save_extra_forms.append('email')

        if not password or not email:
            self._update_extra_form_errors()

        return all([profile, password, email])

    def save(self, request, *args, **kwargs):
        if 'email' in self.save_extra_forms:
            self.email_change_form.save(request, *args, **kwargs)
            self.email_changed = True
        if 'password' in self.save_extra_forms:
            self.password_change_form.save(*args, **kwargs)
            self.password_changed = True
        return super(ExtendedProfileForm, self).save(*args, **kwargs)

