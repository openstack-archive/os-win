#  Copyright 2015 Cloudbase Solutions Srl
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

import mock
from oslotest import base

from os_win.utils.compute import vmutils10


class VMUtils10TestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V VMUtils10 class."""

    def setUp(self):
        super(VMUtils10TestCase, self).setUp()
        self._vmutils = vmutils10.VMUtils10()
        self._vmutils._conn = mock.MagicMock()

    def test_set_secure_boot_CA_required(self):
        vs_data = mock.MagicMock()
        mock_vssd = self._vmutils._conn.Msvm_VirtualSystemSettingData
        mock_vssd.return_value = [
            mock.MagicMock(SecureBootTemplateId=mock.sentinel.template_id)]

        self._vmutils._set_secure_boot(vs_data, msft_ca_required=True)

        self.assertTrue(vs_data.SecureBootEnabled)
        self.assertEqual(mock.sentinel.template_id,
                         vs_data.SecureBootTemplateId)
        mock_vssd.assert_called_once_with(
            ElementName=self._vmutils._UEFI_CERTIFICATE_AUTH)
