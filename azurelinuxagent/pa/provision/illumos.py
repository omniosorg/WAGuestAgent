#
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
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.conf as conf
from azurelinuxagent.pa.provision.default import ProvisionHandler
from azurelinuxagent.common.exception import ProvisionError, ProtocolError
import azurelinuxagent.common.utils.fileutil as fileutil

class illumosProvisionHandler(ProvisionHandler):
    def __init__(self):
        super(illumosProvisionHandler, self).__init__()

    def config_user_account(self, ovfenv):
        logger.info('"config_user_account" not supported.')
