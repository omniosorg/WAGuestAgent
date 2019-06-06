# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
# Copyright (c) 2017 by Delphix. All rights reserved.
# Copyright 2019 Joyent, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.4+ and Openssl 1.0+
#

import azurelinuxagent.common.utils.fileutil as fileutil
from azurelinuxagent.pa.deprovision.default import DeprovisionHandler, \
                                                   DeprovisionAction

class illumosDeprovisionHandler(DeprovisionHandler):
    def __init__(self):
        super(illumosDeprovisionHandler, self).__init__()

    def setup(self, deluser):
        warnings, actions = super(illumosDeprovisionHandler, self).setup(deluser)

        #
        # Disable mgmt to prevent it from calling devfsadm periodically,
        # which recreates /ect/path_to_inst and leaves the vm in a bad
        # state on startup.
        #
        warnings.append("WARNING! The illumos Management service will be stopped.")
        actions.append(DeprovisionAction(self.osutil.stop_mgmt_service))
        actions.append(DeprovisionAction(self.osutil.clear_ips_uuid))

        files_to_del = [
            #
            # Remove DHCP files, which will be recreated by dhcpagent
            # (or one of it's supporting libraries) when it acquires a
            # new lease.
            #
            '/etc/dhcp/*.dhc',
            #
            # Removing this files will cause the kernel to fall back to
            # a "reconfigure" mode on the next boot.
            #
            '/etc/path_to_inst',
            #
            # Remove dlpx-app-gate files, which will be recreated by
            # "dxsvcinit configure" on reboot.
            #
            '/etc/engine.install',
            '/etc/challenge_response.key',
            '/etc/engine-code',
            #
            # Remove history of previously run Bash commands.
            #
            '/root/.bash_history'
            #
            # XXX KEBE ASKS --> more?!?  SSH keys?
            #
        ]

        for f in files_to_del:
            warnings.append("WARNING! {0} will be removed.".format(f))
        actions.append(DeprovisionAction(fileutil.rm_files, files_to_del))

        return warnings, actions

