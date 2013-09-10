# Copyright (C) 2013 GRNET S.A. All rights reserved.
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


astakos_services = {
    'astakos_account': {
        'type': 'account',
        'component': 'astakos',
        'prefix': 'account',
        'public': True,
        'endpoints': [
            {'versionId': 'v1.0',
             'publicURL': None},
        ],
        'resources': {
            'pending_app': {
                'desc': "Number of pending project applications",
                'name': "astakos.pending_app",
                'service_type': "account",
                'service_origin': "astakos_account",
                'allow_in_projects': False},
            },
        },

    'astakos_identity': {
        'type': 'identity',
        'component': 'astakos',
        'prefix': 'identity',
        'public': True,
        'endpoints': [
            {'versionId': 'v2.0',
             'publicURL': None},
        ],
        'resources': {},
    },

    'astakos_weblogin': {
        'type': 'astakos_weblogin',
        'component': 'astakos',
        'prefix': 'weblogin',
        'public': True,
        'endpoints': [
            {'versionId': '',
             'publicURL': None},
        ],
    },

    'astakos_ui': {
        'type': 'astakos_ui',
        'component': 'astakos',
        'prefix': 'ui',
        'public': False,
        'endpoints': [
            {'versionId': '',
             'publicURL': None},
        ],
    },
}
