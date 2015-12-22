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

from os_win._i18n import _
from os_win import constants
from os_win import exceptions
from os_win.utils.compute import vmutils
from oslo_utils import units


class VMUtils10(vmutils.VMUtils):

    _UEFI_CERTIFICATE_AUTH = 'MicrosoftUEFICertificateAuthority'
    _SERIAL_PORT_SETTING_DATA_CLASS = "Msvm_SerialPortSettingData"

    _remote_fx_res_map = {
        constants.REMOTEFX_MAX_RES_1024x768: 0,
        constants.REMOTEFX_MAX_RES_1280x1024: 1,
        constants.REMOTEFX_MAX_RES_1600x1200: 2,
        constants.REMOTEFX_MAX_RES_1920x1200: 3,
        constants.REMOTEFX_MAX_RES_2560x1600: 4,
        constants.REMOTEFX_MAX_RES_3840x2160: 5
    }

    _remotefx_max_monitors_map = {
        # defines the maximum number of monitors for a given
        # resolution
        constants.REMOTEFX_MAX_RES_1024x768: 8,
        constants.REMOTEFX_MAX_RES_1280x1024: 8,
        constants.REMOTEFX_MAX_RES_1600x1200: 4,
        constants.REMOTEFX_MAX_RES_1920x1200: 4,
        constants.REMOTEFX_MAX_RES_2560x1600: 2,
        constants.REMOTEFX_MAX_RES_3840x2160: 1
    }

    _remotefx_vram_vals = [64 * units.Mi, 128 * units.Mi, 256 * units.Mi,
                           512 * units.Mi, 1024 * units.Mi]

    def vm_gen_supports_remotefx(self, vm_gen):
        """RemoteFX is supported on both generation 1 and 2 virtual
        machines for Windows 10 / Windows Server 2016.

        :returns: True
        """
        return True

    def _validate_remotefx_params(self, monitor_count, max_resolution,
                                  vram_bytes=None):
        super(VMUtils10, self)._validate_remotefx_params(monitor_count,
                                                         max_resolution)
        if vram_bytes not in self._remotefx_vram_vals:
            raise exceptions.HyperVRemoteFXException(
                _("Unsuported RemoteFX VRAM value: %(requested_value)s."
                  "The supported VRAM values are: %(supported_values)s") %
                {'requested_value': vram_bytes,
                 'supported_values': self._remotefx_vram_vals})

    def _add_3d_display_controller(self, vm, monitor_count,
                                   max_resolution, vram_bytes=None):
        synth_3d_disp_ctrl_res = self._get_new_resource_setting_data(
            self._SYNTH_3D_DISP_CTRL_RES_SUB_TYPE,
            self._SYNTH_3D_DISP_ALLOCATION_SETTING_DATA_CLASS)

        synth_3d_disp_ctrl_res.MaximumMonitors = monitor_count
        synth_3d_disp_ctrl_res.MaximumScreenResolution = max_resolution

        if vram_bytes:
            synth_3d_disp_ctrl_res.VRAMSizeBytes = unicode(vram_bytes)

        self._jobutils.add_virt_resource(synth_3d_disp_ctrl_res, vm)

    def _vm_has_s3_controller(self, vm_name):
        return self.get_vm_generation(vm_name) == constants.VM_GEN_1

    def _set_secure_boot(self, vs_data, msft_ca_required):
        vs_data.SecureBootEnabled = True
        if msft_ca_required:
            uefi_data = self._conn.Msvm_VirtualSystemSettingData(
                ElementName=self._UEFI_CERTIFICATE_AUTH)[0]
            vs_data.SecureBootTemplateId = uefi_data.SecureBootTemplateId
