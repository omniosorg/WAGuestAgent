# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
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
#
import azurelinuxagent.common.logger as logger
from azurelinuxagent.daemon.resourcedisk.default import ResourceDiskHandler


class illumosResourceDiskHandler(ResourceDiskHandler):

    def __init__(self):  # pylint: disable=W0235
        super(illumosResourceDiskHandler, self).__init__()

    def activate_resource_disk(self):
        logger.error("Activation of resource disk not supported.")

