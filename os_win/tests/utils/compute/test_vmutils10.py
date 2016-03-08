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

from os_win import constants
from os_win import exceptions
from os_win.tests import test_base
from os_win.utils.compute import vmutils10


class VMUtils10TestCase(test_base.OsWinBaseTestCase):
    """Unit tests for the Hyper-V VMUtils10 class."""

    def setUp(self):
        super(VMUtils10TestCase, self).setUp()
        self._vmutils = vmutils10.VMUtils10()
        self._vmutils._conn_attr = mock.MagicMock()

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

    def test_vm_gen_supports_remotefx(self):
        ret = self._vmutils.vm_gen_supports_remotefx(mock.sentinel.VM_GEN)

        self.assertTrue(ret)

    def test_validate_remotefx_monitor_count(self):
        self.assertRaises(exceptions.HyperVRemoteFXException,
                          self._vmutils._validate_remotefx_params,
                          10, constants.REMOTEFX_MAX_RES_1024x768)

    def test_validate_remotefx_max_resolution(self):
        self.assertRaises(exceptions.HyperVRemoteFXException,
                          self._vmutils._validate_remotefx_params,
                          1, '1024x700')

    def test_validate_remotefx_vram(self):
        self.assertRaises(exceptions.HyperVRemoteFXException,
                          self._vmutils._validate_remotefx_params,
                          1, constants.REMOTEFX_MAX_RES_1024x768,
                          vram_bytes=10000)

    @mock.patch.object(vmutils10.VMUtils10, 'get_vm_generation')
    def _test_vm_has_s3_controller(self, vm_gen, mock_get_vm_gen):
        mock_get_vm_gen.return_value = vm_gen
        return self._vmutils._vm_has_s3_controller(mock.sentinel.fake_vm_name)

    def test_vm_has_s3_controller_gen1(self):
        self.assertTrue(self._test_vm_has_s3_controller(constants.VM_GEN_1))

    def test_vm_has_s3_controller_gen2(self):
        self.assertFalse(self._test_vm_has_s3_controller(constants.VM_GEN_2))
