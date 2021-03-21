# Microsoft Azure Linux Agent
#
# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#

import os
import time
from azurelinuxagent.common.exception import OSUtilError
import azurelinuxagent.common.utils.fileutil as fileutil
import azurelinuxagent.common.utils.shellutil as shellutil
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.osutil.default import DefaultOSUtil

class illumosOSUtil(DefaultOSUtil):
    def __init__(self):
        super(illumosOSUtil, self).__init__()

    #
    # The methods that emit an "error" are not expected to be called
    # when the agent is running on illumos. The code paths that could
    # have called them have been disabled either by configuration file
    # settings, or code changes to other parts of the codebase.
    #

    def useradd(self, username, expiration=None, comment=None):
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

        self._run_command_without_raising(['passwd', '-N', username])

    def chpasswd(self, username, password, crypt_id=6, salt_len=10):
        logger.error('"chpasswd" not supported.')

    def conf_sshd(self, disable_password):
        logger.error('"conf_sshd" not supported.')

    def del_root_password(self):
        logger.error('"del_root_password" not supported.')

    def clear_ips_uuid(self):
        if not os.path.isfile('/var/pkg/pkg5.image'): return
        fileutil.update_conf_file("/var/pkg/pkg5.image", "last_uuid", "")

    def stop_mgmt_service(self):
        logger.error('"stop_mgmt_service" not supported.')

    def start_agent_service(self):
        return shellutil.run("svcadm enable -st svc:/system/virtualization/waagent", chk_err=False)

    def stop_agent_service(self):
        return shellutil.run("svcadm disable -st svc:/system/virtualization/waagent", chk_err=False)

    def register_agent_service(self):
        return shellutil.run("svcadm enable svc:/system/virtualization/waagent", chk_err=False)

    def unregister_agent_service(self):
        return shellutil.run("svcadm disable svc:/system/virtualization/waagent", chk_err=False)

    def set_admin_access_to_ip(self, dest_ip):
        logger.warn('"set_admin_access_to_ip" not supported.')

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

    def restart_if(self, ifname):
        return shellutil.run("ipadm refresh-addr {0}".format(ifname))

    def publish_hostname(self, hostname):
        #
        # We intentionally leave this method unimplemented as we don't
        # rely on the DHCP for providing the system's hostname. Instead,
        # we rely on the "set_hostname" function to configure the
        # "/etc/nodename" file, as well as configure the "identity:node"
        # service to always use that file's contents to configure the
        # hostname of the system.
        #
        logger.warn('"publish_hostname" not supported.')

    def set_dhcp_hostname(self, hostname):
        #
        # We initentionally leave this function unimplemented, for the
        # same reason that we leave "publish_hostname" unimplemented;
        # see the comment in that function for more details.
        #
        logger.warn('"set_dhcp_hostname" not supported.')

    def restart_ssh_service(self):
        ret = shellutil.run('svcadm disable -s svc:/network/ssh')
        if ret == 0:
            return shellutil.run('svcadm enable -s svc:/network/ssh')
        else:
            return ret

    def enable_serial_console(self):
        #
        # For now, assume your illumos distro's VHD or image ALREADY HAS
        # serial console enabled.
        #
        return True

    def reboot_system(self):
        logger.info('Rebooting system')
        ret = shellutil.run('reboot')
        if ret != 0:
            logger.error('Failed to reboot the system')

    def get_dhcp_lease_endpoint(self):
        ret = shellutil.run_get_output('/sbin/dhcpinfo 245')

        #
        # The dhcpinfo command can fail if the Azure specific DHCP
        # option of 245 isn't contained in the /etc/dhcp/inittab file.
        # Additionally, if the command succeeds, it's possible that the
        # option wasn't found, in which case dhcpinfo will produce no
        # output.
        #
        if ret[0] == 0 and ret[1] != '':
            return ret[1].strip()
        else:
            return None

    def del_account(self, username):
        if self.is_sys_user(username):
            logger.error("{0} is a system user. Will not delete it.", username)
        self._run_command_without_raising(['userdel', '-r', username])
        self.conf_sudoer(username, remove=True)

    def is_selinux_system(self):
        return False

    def get_dvd_mount_options(self):
        return ['-o', 'ro', '-F', 'udfs']

    def get_dvd_device(self, dev_dir='/dev'):
        cmd = "rmformat -l | grep 'Logical Node' | awk '{print $NF}' | sed -e 's/rdsk/dsk/'"
        ret = shellutil.run_get_output(cmd)
        if ret[0] == 0:
            device = ret[1].strip()
            logger.info('Using dvd device: "{0}"'.format(device))
            return device
        else:
            raise OSUtilError('Failed to determine DVD device.')

    def eject_dvd(self, chk_err=True):
        logger.warn('"eject_dvd" not supported.')

    def get_if_mac(self, ifname):
        data = self._get_net_info()
        if data[0] == ifname:
            return data[2].replace(':', '').upper()
        return None

    def get_first_if(self):
        return self._get_net_info()[:2]

    def route_add(self, net, mask, gateway):
        #
        # The "Router" DHCP option is provided by the Azure cloud's DHCP
        # server, so instead of having the Agent modify the routes, we
        # rely on the DHCP client on the DE to do this.
        #
        logger.warn('"route_add" not supported.')

    def is_missing_default_route(self):
        return False

    #
    # When probing for the wireserver endpoint using DHCP, the DHCP
    # services doesn't need to be disabled when running on illumos.
    # Additionally, this won't normally be called, since the DHCP cache
    # will normally be used to determine the wireserver endpoint; and
    # thus, we won't need to probe for the endpoint using DHCP requests.
    #
    def is_dhcp_enabled(self):
        return False

    def allow_dhcp_broadcast(self):
        pass

    def get_dhcp_pid(self):
        ret = shellutil.run_get_output("pgrep -c $(svcs -H -o ctid svc:/network/dhcp-client)", chk_err=False)
        return ret[1] if ret[0] == 0 else None

    def set_scsi_disks_timeout(self, timeout):
        pattern = r'^set sd:sd_io_time *= *(.*)$'

        #
        # Since changes to this setting require a reboot to take effect,
        # we're careful to only change the value and print the warning
        # message if the current value is different than the desired
        # value. Essentially, we only want to print the warning message
        # that suggest a reboot is required, if we actually modify the
        # value that's already set; otherwise, we could unnecessarily
        # suggest rebooting the system when that's not actually necessary.
        #

        for sf in ['/etc/system', '/etc/system.d/.self-assembly']:
                if not os.path.isfile(sf): continue
                match = fileutil.findre_in_file(sf, pattern)
                if match:
                    try:
                        current = int(match.group(1))
                    except ValueError:
                        raise OSUtilError('Unable to parse existing SCSI disk timeout: "{0}".'.format(match.group(1)))

                    if current == int(timeout):
                        return

        logger.warn('Updating SCSI disk timeout to desired value of "{0}", reboot required to take effect.'.format(timeout))
        fileutil.write_file('/etc/system.d/system:virtualization:azure-agent',
            'set sd:sd_io_time = {0}\n'.format(timeout))

    def check_pid_alive(self, pid):
        return shellutil.run("ps -p {0}".format(pid), chk_err=False) == 0

    @staticmethod
    def read_route_table():
        # Not currently implemented for illumos
        return []

    @staticmethod
    def _get_net_info():
        iface = ''
        inet = ''
        mac = ''

        err, output = shellutil.run_get_output('dladm show-ether -p -o LINK', chk_err=False)
        if err:
            raise OSUtilError("Can't find ether interface:{0}".format(output))
        ifaces = output.split()
        if not ifaces:
            raise OSUtilError("Can't find ether interface.")
        iface = ifaces[0]

        err, output = shellutil.run_get_output('dladm show-phys -m -p -o address ' + iface, chk_err=False)
        if err:
            raise OSUtilError("Can't get mac address for interface:{0}".format(iface))
        macs = output.split()
        if not macs:
            raise OSUtilError("Can't find mac address.")
        mac = macs[0]

        #
        # It's possible for the output from "dladm show-phys" to output
        # a mac address, such that each octet is not two characters
        # (e.g. "2:dc:0:0:23:ff"). Certain parts of the agent expect
        # each octet of the mac address to be two hex characters long,
        # so we're forcing the address returned by this function to
        # always have two character long octets.
        #
        mac = ":".join(map(lambda x: "{0:02x}".format(int(x, 16)), mac.split(":")))

        err, output = shellutil.run_get_output('ipadm show-addr -p -o addr ' + iface + '/', chk_err=False)
        if err:
            raise OSUtilError("Can't get ip address for interface:{0}".format(iface))
        ips = output.split()
        if not ips:
            raise OSUtilError("Can't find ip address.")
        ip = ips[0].split('/')[0]

        logger.verbose("Interface info: ({0},{1},{2})", iface, ip, mac)

        return iface, ip, mac

    def device_for_ide_port(self, port_id):
        logger.warn('"device_for_ide_port" not supported.')

    def get_instance_id(self):
        cmd = 'smbios -t 1'

        err, output = shellutil.run_get_output(cmd, chk_err=False)
        if err:
            return ""

        for line in output.split('\n'):
            if not line.strip().startswith('UUID:'): continue
            return line.split(' ')[1]

        return ""

    def get_firewall_will_wait(self):
        return ""

    def get_firewall_dropped_packets(self, dst_ip=None):
        return -1

