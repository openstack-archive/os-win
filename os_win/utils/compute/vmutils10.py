# Copyright 2015 Cloudbase Solutions Srl
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from os_win.utils.compute import vmutils


class VMUtils10(vmutils.VMUtils):

    _UEFI_CERTIFICATE_AUTH = 'MicrosoftUEFICertificateAuthority'

    def _set_secure_boot(self, vs_data, msft_ca_required):
        vs_data.SecureBootEnabled = True
        if msft_ca_required:
            uefi_data = self._conn.Msvm_VirtualSystemSettingData(
                ElementName=self._UEFI_CERTIFICATE_AUTH)[0]
            vs_data.SecureBootTemplateId = uefi_data.SecureBootTemplateId
