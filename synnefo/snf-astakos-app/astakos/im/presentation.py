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

from astakos.im import settings
from synnefo.lib.utils import dict_merge

RESOURCES = {
    'groups': {
        'compute': {
            'help_text': ('Compute resources '
                          '(amount of VMs, CPUs, RAM, System disk) '),
            'is_abbreviation': False,
            'report_desc': '',
            'verbose_name': 'compute',
        },
        'storage': {
            'help_text': ('Storage resources '
                          '(amount of space to store files on Pithos) '),
            'is_abbreviation': False,
            'report_desc': '',
            'verbose_name': 'storage',
        },
        'network': {
            'help_text': ' Network resources (number of Private Networks)  ',
            'is_abbreviation': False,
            'report_desc': '',
            'verbose_name': 'network',
        },
    },
    'resources': {
        'pithos.diskspace': {
            'help_text': ('This is the space on Pithos for storing files '
                          'and VM Images. '),
            'help_text_input_each': ('This is the total amount of space on '
                                     'Pithos that will be granted to each '
                                     'user of this Project '),
            'is_abbreviation': False,
            'report_desc': 'Storage Space',
            'placeholder': 'eg. 10GB',
            'verbose_name': 'Storage Space',
            'group': 'storage'
        },
        'cyclades.disk': {
            'help_text': ('This is the System Disk that the VMs have that '
                          'run the OS '),
            'help_text_input_each': ("This is the total amount of System Disk "
                                     "that will be granted to each user of "
                                     "this Project (this refers to the total "
                                     "System Disk of all VMs, not each VM's "
                                     "System Disk)  "),
            'is_abbreviation': False,
            'report_desc': 'System Disk',
            'placeholder': 'eg. 5GB, 2GB etc',
            'verbose_name': 'System Disk',
            'group': 'compute'
        },
        'cyclades.ram': {
            'help_text': 'RAM used by VMs ',
            'help_text_input_each': ('This is the total amount of RAM that '
                                     'will be granted to each user of this '
                                     'Project (on all VMs)  '),
            'is_abbreviation': True,
            'report_desc': 'RAM',
            'placeholder': 'eg. 4GB',
            'verbose_name': 'ram',
            'group': 'compute'

        },
        'cyclades.cpu': {
            'help_text': 'CPUs used by VMs ',
            'help_text_input_each': ('This is the total number of CPUs that '
                                     'will be granted to each user of this '
                                     'Project (on all VMs)  '),
            'is_abbreviation': True,
            'report_desc': 'CPUs',
            'placeholder': 'eg. 1',
            'verbose_name': 'cpu',
            'group': 'compute'

        },
        'cyclades.vm': {
            'help_text': ('These are the VMs one can create on the '
                          'Cyclades UI '),
            'help_text_input_each': ('This is the total number of VMs that '
                                     'will be granted to each user of this '
                                     'Project '),
            'is_abbreviation': True,
            'report_desc': 'Virtual Machines',
            'placeholder': 'eg. 2',
            'verbose_name': 'vm',
            'group': 'compute'

        },
        'cyclades.network.private': {
            'help_text': ('These are the Private Networks one can create on '
                          'the Cyclades UI. '),
            'help_text_input_each': ('This is the total number of Private '
                                     'Networks that will be granted to each '
                                     'user of this Project '),
            'is_abbreviation': False,
            'report_desc': 'Private Networks',
            'placeholder': 'eg. 1',
            'verbose_name': 'Private Network',
            'group': 'network'

        },
        'astakos.pending_app': {
            'help_text': ('Pending project applications limit'),
            'help_text_input_each': ('Total pending project applications user '
                                     'is allowed to create'),
            'is_abbreviation': False,
            'report_desc': 'Pending Project Applications',
            'placeholder': 'eg. 2',
            'verbose_name': 'pending project application',
            'group': 'accounts'

        },
    },
    'groups_order': ['storage', 'compute', 'network', 'accounts'],
    'resources_order': ['pithos.diskspace',
                        'cyclades.disk',
                        'cyclades.cpu',
                        'cyclades.ram',
                        'cyclades.vm',
                        'cyclades.network.private',
                        'astakos.pending_app'
                        ],
    'exclude_from_usage': ['astakos.pending_app']
}

# extend from settings
RESOURCES = dict_merge(RESOURCES, settings.RESOURCES_META)


def component_defaults(service_name):
    """
    Metadata for unkown services
    """
    return {
        'name': service_name,
        'order': 1000,
        'verbose_name': service_name.title(),
        'cloudbar': {
            'show': True,
            'title': service_name
        },
        'dashboard': {
            'show': True,
            'order': 1000,
            'description': '%s service' % service_name
        }
    }


COMPONENTS = {
    'astakos': {
        'order': 1,
        'dashboard': {
            'order': 3,
            'show': True,
            'description': "Access the dashboard from the top right corner "
                           "of your screen. Here you can manage your profile, "
                           "see the usage of your resources and manage "
                           "projects to share virtual resources with "
                           "colleagues."
        },
        'cloudbar': {
            'show': False
        }
    },
    'pithos': {
        'order': 2,
        'dashboard': {
            'order': 1,
            'show': True,
            'description': "Pithos is the File Storage service. "
                           "Click to start uploading and managing your "
                           "files on the cloud."
        },
        'cloudbar': {
            'show': True
        }
    },
    'cyclades': {
        'order': 3,
        'dashboard': {
            'order': 2,
            'show': True,
            'description': "Cyclades is the Compute and Network Service. "
                           "Click to start creating Virtual Machines and "
                           "connect them to arbitrary Networks."
        },
        'cloudbar': {
            'show': True
        }
    }
}


PROJECT_MEMBER_JOIN_POLICIES = {
    1: 'automatically accepted',
    2: 'owner accepts',
    3: 'closed',
}


PROJECT_MEMBER_LEAVE_POLICIES = {
    1: 'automatically accepted',
    2: 'owner accepts',
    3: 'closed',
}
