# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
# Copyright (c) 2016, 2017 by Delphix. All rights reserved.
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
# Requires Python 2.6+ and Openssl 1.0+

import socket
import struct
import binascii
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.utils.textutil as textutil
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.future import ustr


class illumosOSUtil(DefaultOSUtil):

    def __init__(self):
        super(illumosOSUtil, self).__init__()
        self._scsi_disks_timeout_set = False
        self.jit_enabled = True

    @staticmethod
    def get_agent_bin_path():
        return "/usr/lib/hyperv"

    def start_service(self, fmri):
        return shellutil.run('svcadm enable -s {1}'.format(fmri))

    def stop_service(self, fmri):
        return shellutil.run('svcadm disable -s {1}'.format(fmri))

    def restart_service(self, fmri):
        ret = self.stop_service(fmri)
        if ret != 0: return ret
        return self.start_service(fmri)

    def clear_ips_uuid(self):
        if not os.path.isfile('/var/pkg/pkg5.image'): return
        fileutil.update_conf_file("/var/pkg/pkg5.image", "last_uuid", "")

    def start_agent_service(self):
        return self.start_service('svc:/system/virtualization/waagent')

    def stop_agent_service(self):
        return self.stop_service('svc:/system/virtualization/waagent')

    def register_agent_service(self):
        return self.start_agent_service()

    def unregister_agent_service(self):
        return self.stop_agent_service()

    def set_hostname(self, hostname):
        #
        # In order for the identity-node service to properly detect the
        # hostname from the contents of /etc/nodename, the file needs to
        # contain a newline after the hostname. Otherwise, the service
        # will simply assign "unknown" as the hostname for the system.
        #
        fileutil.write_file('/etc/nodename', '{0}\n'.format(hostname))

        # Make it happen NOW.
        ret = shellutil.run('uname -S {0}'.format(hostname))
        if ret:
            raise OSUtilError('Unable to set hostname to {0}.'.format(hostname))

        #
        # Unfortunately, there isn't a way to cause the service refresh
        # executed above a synchronous operation. Thus, without this
        # loop, it would be possible for this function to return without
        # having the hostname having been updated yet.
        #
        # Setting the hostname on the other platforms is a synchronous
        # operation, so we've opted to enforce this fuction as being
        # synchronus as well.
        #
        actual = None
        for i in range(0, 10):
            ret = shellutil.run_get_output('hostname')
            if ret[0] == 0:
                actual = ret[1].strip()
            else:
                raise OSUtilError('Unable to retrieve hostname')

            if hostname == actual:
                break
            else:
                time.sleep(1)

        if actual != hostname:
            raise OSUtilError('Unable to modify hostname to the desired value')

    def restart_ssh_service(self):
        return self.restart_service('svc:/network/ssh:default')

    def useradd(self, username, expiration=None, comment=None):
        """
        Create user account with 'username'
        """
        userentry = self.get_userentry(username)
        if userentry is not None:
            logger.warn("User {0} already exists, skip useradd", username)
            return

        cmd = ['useradd', '-mz']
        if expiration is not None:
            cmd.extend(['-e', expiration])
        if comment is not None:
            cmd.extend(['-c', comment])
        cmd.append(username)

        self._run_command_raising_OSUtilError(cmd,
            err_msg="Failed to create user account:{0}".format(username))

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.", username)
        self._run_command_without_raising(['userdel', '-r', username])
        self.conf_sudoer(username, remove=True)

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        if self.is_sys_user(username):
            raise OSUtilError(("User {0} is a system user, "
                               "will not set password.").format(username))
        passwd_hash = textutil.gen_password_hash(password, crypt_id, salt_len)

        logger.error('"chpasswd" not supported.')

        #self._run_command_raising_OSUtilError(
        #   ['pw', 'usermod', username, '-H', '0'], cmd_input=passwd_hash,
        #   err_msg="Failed to set password for {0}".format(username))

    def del_root_password(self):
        err = shellutil.run('passwd -N root')
        if err:
            raise OSUtilError("Failed to delete root password:"
                "Failed to update password database.")

    def get_if_mac(self, ifname):
        _, _, mac = self._get_net_info(ifname)
        return mac

    def get_first_if(self):
        return self._get_net_info()[:2]

    @staticmethod
    def _get_net_info(iface=None):
        ip = mac = None

        cmd = 'dladm show-phys -mp -o link,address'.format(iface)
        if iface:
            cmd += ' {}'.format(iface)

        err, output = shellutil.run_get_output(cmd, chk_err=False)
        if err:
            raise OSUtilError("Can't retrieve interface information")

        try:
            iface, mac = output.split().pop(0).split(':', maxsplit=1)
        except:
            raise OSUtilError("Can't find interface information")

        #
        # It's possible for the output from "dladm show-phys" to output
        # a mac address, such that each octet is not two characters
        # (e.g. "2:dc:0:0:23:ff"). Certain parts of the agent expect
        # each octet of the mac address to be two hex characters long,
        # so we're forcing the address returned by this function to
        # always have two character long octets.
        #
        mac = ":".join(map(lambda x: "{0:02x}".format(int(x, 16)),
            mac.split(":")))

        err, output = shellutil.run_get_output(
            'ipadm show-addr -p -o addr {}/'.format(iface), chk_err=False)
        if err:
            raise OSUtilError(
                "Can't get ip address for interface:{0}".format(iface))
        try:
            ip = output.split().pop(0).split('/')[0]
        except:
            raise OSUtilError("Can't find ip address.")

        logger.verbose("Interface info: ({0},{1},{2})", iface, ip, mac)

        return iface, ip, mac

    @staticmethod
    def read_route_table():
        # Not currently implemented for illumos
        return []

    @staticmethod
    def get_list_of_routes(route_table):
        # Not currently implemented for illumos
        return []

    def get_primary_interface(self):
        """
        Get the name of the primary interface, which is the one with the
        default route attached to it.
        """
        cmd = 'route -n get default'

        err, output = shellutil.run_get_output(cmd, chk_err=False)
        if err:
            raise OSUtilError("Can't retrieve route information")

        for line in output.split():
            if not line.strip().startswith('interface:'): continue
            return line.split(' ')[1]

        return None

    def is_primary_interface(self, ifname):
        """
        Indicate whether the specified interface is the primary.
        :param ifname: the name of the interface - eth0, lo, etc.
        :return: True if this interface binds the default route
        """
        return self.get_primary_interface() == ifname

    def is_loopback(self, ifname):
        """
        Determine if a named interface is loopback.
        """
        return ifname.startswith("lo")

    def route_add(self, net, mask, gateway):
        logger.warn('"route_add" not supported.')

    def is_missing_default_route(self):
        return self.get_primary_interface() is None

    def is_dhcp_enabled(self):
        return False

    def start_dhcp_service(self):
        pass

    def allow_dhcp_broadcast(self):
        pass

    def set_route_for_dhcp_broadcast(self, ifname):
        pass

    def remove_route_for_dhcp_broadcast(self, ifname):
        pass

    def get_dhcp_pid(self):
        pass

    def is_selinux_system(self):
        return False

    def get_dvd_mount_options(self):
        return ['-o', 'ro', '-F', 'udfs']

    def get_dvd_device(self):
        err, output = shellutil.run_get_output('rmformat -l', chk_err=False)

        raise OSUtilError('Failed to determine DVD device.')


