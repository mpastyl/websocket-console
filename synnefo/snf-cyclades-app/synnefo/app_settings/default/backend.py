# -*- coding: utf-8 -*-
#
# Ganeti backend configuration
###################################

# This prefix gets used when determining the instance names
# of Synnefo VMs at the Ganeti backend.
# The dash must always appear in the name!
BACKEND_PREFIX_ID = "snf-"

# The following dictionary defines deployment-specific
# arguments to the RAPI CreateInstance call.
# At a minimum it should contain the
# 'os' and 'hvparams' keys.
#
# More specifically:
# a) os:
#    The OS provider to use (customized Ganeti Instance Image)
# b) hvparams:
#    Hypervisor-specific parameters (serial_console = False, see #785),
#    for each hypervisor(currently 'kvm', 'xen-pvm' and 'xen-hvm').
# c) If using the DRBD disk_template, you may want to include
#    wait_for_sync = False (see #835).
#
GANETI_CREATEINSTANCE_KWARGS = {
    'os': 'snf-image+default',
    'hvparams': {"kvm": {'serial_console': False},
                 "xen-pvm": {},
                 "xen-hvm": {}},
    'wait_for_sync': False}

# If True, qemu-kvm will hotplug a NIC when connecting a vm to
# a network. This requires qemu-kvm=1.0.
GANETI_USE_HOTPLUG = False

# This module implements the strategy for allocating a vm to a backend
BACKEND_ALLOCATOR_MODULE = "synnefo.logic.allocators.default_allocator"
# Refresh backend statistics timeout, in minutes, used in backend allocation
BACKEND_REFRESH_MIN = 15
