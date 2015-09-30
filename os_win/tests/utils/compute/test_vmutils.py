# Copyright 2014 Cloudbase Solutions Srl
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

import mock
from oslotest import base

from six.moves import range  # noqa

from os_win import exceptions
from os_win.utils.compute import vmutils
from os_win.utils import constants


class VMUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V VMUtils class."""

    _FAKE_VM_NAME = 'fake_vm'
    _FAKE_MEMORY_MB = 2
    _FAKE_VCPUS_NUM = 4
    _FAKE_JOB_PATH = 'fake_job_path'
    _FAKE_RET_VAL = 0
    _FAKE_PATH = "fake_path"
    _FAKE_CTRL_PATH = 'fake_ctrl_path'
    _FAKE_CTRL_ADDR = 0
    _FAKE_DRIVE_ADDR = 0
    _FAKE_MOUNTED_DISK_PATH = 'fake_mounted_disk_path'
    _FAKE_VM_PATH = "fake_vm_path"
    _FAKE_VHD_PATH = "fake_vhd_path"
    _FAKE_DVD_PATH = "fake_dvd_path"
    _FAKE_VOLUME_DRIVE_PATH = "fake_volume_drive_path"
    _FAKE_VM_UUID = "04e79212-39bc-4065-933c-50f6d48a57f6"
    _FAKE_INSTANCE = {"name": _FAKE_VM_NAME,
                      "uuid": _FAKE_VM_UUID}
    _FAKE_SNAPSHOT_PATH = "fake_snapshot_path"
    _FAKE_RES_DATA = "fake_res_data"
    _FAKE_HOST_RESOURCE = "fake_host_resource"
    _FAKE_CLASS = "FakeClass"
    _FAKE_RES_PATH = "fake_res_path"
    _FAKE_RES_NAME = 'fake_res_name'
    _FAKE_ADDRESS = "fake_address"
    _FAKE_DYNAMIC_MEMORY_RATIO = 1.0

    _FAKE_SUMMARY_INFO = {'NumberOfProcessors': 4,
                          'EnabledState': 2,
                          'MemoryUsage': 2,
                          'UpTime': 1}

    _DEFINE_SYSTEM = 'DefineSystem'
    _DESTROY_SYSTEM = 'DestroySystem'
    _DESTROY_SNAPSHOT = 'DestroySnapshot'
    _SETTING_TYPE = 'VirtualSystemType'
    _VM_GEN = constants.VM_GEN_2

    _VIRTUAL_SYSTEM_TYPE_REALIZED = 'Microsoft:Hyper-V:System:Realized'

    def setUp(self):
        self._vmutils = vmutils.VMUtils()
        self._vmutils._conn = mock.MagicMock()
        self._vmutils._jobutils = mock.MagicMock()

        super(VMUtilsTestCase, self).setUp()

    @mock.patch('os_win.utils.hostutils.HostUtils'
                '.check_min_windows_version')
    @mock.patch.object(vmutils, 'sys')
    @mock.patch.object(vmutils, 'wmi', create=True)
    def test_serial_port_setting_data_win_version_10(self, mock_wmi, mock_sys,
                                                     mock_check_version):
        mock_sys.platform = 'win32'
        mock_check_version.return_value = True
        _vmutils = vmutils.VMUtils()

        self.assertEqual("Msvm_SerialPortSettingData",
                         _vmutils._SERIAL_PORT_SETTING_DATA_CLASS)

    def test_get_vm_summary_info(self):
        self._lookup_vm()
        mock_svc = self._vmutils._conn.Msvm_VirtualSystemManagementService()[0]

        mock_summary = mock.MagicMock()
        mock_svc.GetSummaryInformation.return_value = (self._FAKE_RET_VAL,
                                                       [mock_summary])

        for (key, val) in self._FAKE_SUMMARY_INFO.items():
            setattr(mock_summary, key, val)

        summary = self._vmutils.get_vm_summary_info(self._FAKE_VM_NAME)
        self.assertEqual(self._FAKE_SUMMARY_INFO, summary)

    def _lookup_vm(self):
        mock_vm = mock.MagicMock()
        self._vmutils._lookup_vm_check = mock.MagicMock(
            return_value=mock_vm)
        mock_vm.path_.return_value = self._FAKE_VM_PATH
        return mock_vm

    def test_lookup_vm_ok(self):
        mock_vm = mock.MagicMock()
        self._vmutils._conn.Msvm_ComputerSystem.return_value = [mock_vm]
        vm = self._vmutils._lookup_vm_check(self._FAKE_VM_NAME)
        self.assertEqual(mock_vm, vm)

    def test_lookup_vm_multiple(self):
        mockvm = mock.MagicMock()
        self._vmutils._conn.Msvm_ComputerSystem.return_value = [mockvm, mockvm]
        self.assertRaises(exceptions.HyperVException,
                          self._vmutils._lookup_vm_check,
                          self._FAKE_VM_NAME)

    def test_lookup_vm_none(self):
        self._vmutils._conn.Msvm_ComputerSystem.return_value = []
        self.assertRaises(exceptions.HyperVVMNotFoundException,
                          self._vmutils._lookup_vm_check,
                          self._FAKE_VM_NAME)

    def test_set_vm_memory_static(self):
        self._test_set_vm_memory_dynamic(1.0)

    def test_set_vm_memory_dynamic(self):
        self._test_set_vm_memory_dynamic(2.0)

    def _test_set_vm_memory_dynamic(self, dynamic_memory_ratio):
        mock_vm = self._lookup_vm()

        mock_s = self._vmutils._conn.Msvm_VirtualSystemSettingData()[0]
        mock_s.SystemType = 3

        mock_vmsetting = mock.MagicMock()
        mock_vmsetting.associators.return_value = [mock_s]

        self._vmutils._set_vm_memory(mock_vm, mock_vmsetting,
                                     self._FAKE_MEMORY_MB,
                                     dynamic_memory_ratio)

        self._vmutils._jobutils.modify_virt_resource.assert_called_once_with(
            mock_s, mock_vm)

        if dynamic_memory_ratio > 1:
            self.assertTrue(mock_s.DynamicMemoryEnabled)
        else:
            self.assertFalse(mock_s.DynamicMemoryEnabled)

    def test_soft_shutdown_vm(self):
        mock_vm = self._lookup_vm()
        mock_shutdown = mock.MagicMock()
        mock_shutdown.InitiateShutdown.return_value = (self._FAKE_RET_VAL, )
        mock_vm.associators.return_value = [mock_shutdown]

        self._vmutils.soft_shutdown_vm(self._FAKE_VM_NAME)

        mock_shutdown.InitiateShutdown.assert_called_once_with(
            Force=False, Reason=mock.ANY)
        self._vmutils._jobutils.check_ret_val.assert_called_once_with(
            self._FAKE_RET_VAL, None)

    def test_soft_shutdown_vm_no_component(self):
        mock_vm = self._lookup_vm()
        mock_vm.associators.return_value = []

        self._vmutils.soft_shutdown_vm(self._FAKE_VM_NAME)
        self.assertFalse(self._vmutils._jobutils.check_ret_val.called)

    @mock.patch.object(vmutils.VMUtils, '_get_vm_disks')
    def test_get_vm_storage_paths(self, mock_get_vm_disks):
        self._lookup_vm()
        mock_rasds = self._create_mock_disks()
        mock_get_vm_disks.return_value = ([mock_rasds[0]], [mock_rasds[1]])

        storage = self._vmutils.get_vm_storage_paths(self._FAKE_VM_NAME)
        (disk_files, volume_drives) = storage

        self.assertEqual([self._FAKE_VHD_PATH], disk_files)
        self.assertEqual([self._FAKE_VOLUME_DRIVE_PATH], volume_drives)

    def test_get_vm_disks(self):
        mock_vm = self._lookup_vm()
        mock_vmsettings = [mock.MagicMock()]
        mock_vm.associators.return_value = mock_vmsettings

        mock_rasds = self._create_mock_disks()
        mock_vmsettings[0].associators.return_value = mock_rasds

        (disks, volumes) = self._vmutils._get_vm_disks(mock_vm)

        mock_vm.associators.assert_called_with(
            wmi_result_class=self._vmutils._VIRTUAL_SYSTEM_SETTING_DATA_CLASS)
        mock_vmsettings[0].associators.assert_called_with(
            wmi_result_class=self._vmutils._RESOURCE_ALLOC_SETTING_DATA_CLASS)
        self.assertEqual([mock_rasds[0]], disks)
        self.assertEqual([mock_rasds[1]], volumes)

    def _create_mock_disks(self):
        mock_rasd1 = mock.MagicMock()
        mock_rasd1.ResourceSubType = self._vmutils._HARD_DISK_RES_SUB_TYPE
        mock_rasd1.HostResource = [self._FAKE_VHD_PATH]
        mock_rasd1.Connection = [self._FAKE_VHD_PATH]
        mock_rasd1.Parent = self._FAKE_CTRL_PATH
        mock_rasd1.Address = self._FAKE_ADDRESS
        mock_rasd1.HostResource = [self._FAKE_VHD_PATH]

        mock_rasd2 = mock.MagicMock()
        mock_rasd2.ResourceSubType = self._vmutils._PHYS_DISK_RES_SUB_TYPE
        mock_rasd2.HostResource = [self._FAKE_VOLUME_DRIVE_PATH]

        return [mock_rasd1, mock_rasd2]

    def test_check_admin_permissions(self):
        mock_svc = self._vmutils._conn.Msvm_VirtualSystemManagementService
        mock_svc.return_value = False

        self.assertRaises(exceptions.HyperVAuthorizationException,
                          self._vmutils.check_admin_permissions)

    @mock.patch.object(vmutils.VMUtils, '_set_vm_vcpus')
    @mock.patch.object(vmutils.VMUtils, '_set_vm_memory')
    @mock.patch.object(vmutils.VMUtils, '_get_wmi_obj')
    def test_create_vm(self, mock_get_wmi_obj, mock_set_mem, mock_set_vcpus):
        mock_svc = self._vmutils._conn.Msvm_VirtualSystemManagementService()[0]
        getattr(mock_svc, self._DEFINE_SYSTEM).return_value = (
            None, self._FAKE_JOB_PATH, self._FAKE_RET_VAL)

        mock_vm = mock_get_wmi_obj.return_value
        self._vmutils._conn.Msvm_ComputerSystem.return_value = [mock_vm]

        mock_s = mock.MagicMock()
        setattr(mock_s,
                self._SETTING_TYPE,
                self._VIRTUAL_SYSTEM_TYPE_REALIZED)
        mock_vm.associators.return_value = [mock_s]

        self._vmutils.create_vm(self._FAKE_VM_NAME, self._FAKE_MEMORY_MB,
                                self._FAKE_VCPUS_NUM, False,
                                self._FAKE_DYNAMIC_MEMORY_RATIO,
                                self._VM_GEN,
                                mock.sentinel.instance_path)

        self.assertTrue(getattr(mock_svc, self._DEFINE_SYSTEM).called)
        mock_set_mem.assert_called_with(mock_vm, mock_s, self._FAKE_MEMORY_MB,
                                        self._FAKE_DYNAMIC_MEMORY_RATIO)

        mock_set_vcpus.assert_called_with(mock_vm, mock_s,
                                          self._FAKE_VCPUS_NUM,
                                          False)

    def test_get_vm_scsi_controller(self):
        self._prepare_get_vm_controller(self._vmutils._SCSI_CTRL_RES_SUB_TYPE)
        path = self._vmutils.get_vm_scsi_controller(self._FAKE_VM_NAME)
        self.assertEqual(self._FAKE_RES_PATH, path)

    @mock.patch.object(vmutils.VMUtils, 'get_attached_disks')
    def test_get_free_controller_slot(self, mock_get_attached_disks):
        mock_disk = mock.MagicMock()
        mock_disk.AddressOnParent = 3
        mock_get_attached_disks.return_value = [mock_disk]

        response = self._vmutils.get_free_controller_slot(
            self._FAKE_CTRL_PATH)

        mock_get_attached_disks.assert_called_once_with(
            self._FAKE_CTRL_PATH)

        self.assertEqual(response, 0)

    def test_get_free_controller_slot_exception(self):
        fake_drive = mock.MagicMock()
        type(fake_drive).AddressOnParent = mock.PropertyMock(
            side_effect=range(constants.SCSI_CONTROLLER_SLOTS_NUMBER))

        with mock.patch.object(self._vmutils,
                'get_attached_disks') as fake_get_attached_disks:
            fake_get_attached_disks.return_value = (
                [fake_drive] * constants.SCSI_CONTROLLER_SLOTS_NUMBER)
            self.assertRaises(exceptions.HyperVException,
                              self._vmutils.get_free_controller_slot,
                              mock.sentinel.scsi_controller_path)

    def test_get_vm_ide_controller(self):
        self._prepare_get_vm_controller(self._vmutils._IDE_CTRL_RES_SUB_TYPE)
        path = self._vmutils.get_vm_ide_controller(self._FAKE_VM_NAME,
                                                   self._FAKE_ADDRESS)
        self.assertEqual(self._FAKE_RES_PATH, path)

    def test_get_vm_ide_controller_none(self):
        self._prepare_get_vm_controller(self._vmutils._IDE_CTRL_RES_SUB_TYPE)
        path = self._vmutils.get_vm_ide_controller(
            mock.sentinel.FAKE_VM_NAME, mock.sentinel.FAKE_NOT_FOUND_ADDR)
        self.assertNotEqual(self._FAKE_RES_PATH, path)

    def _prepare_get_vm_controller(self, resource_sub_type):
        mock_vm = self._lookup_vm()
        mock_vm_settings = mock.MagicMock()
        mock_rasds = mock.MagicMock()
        mock_rasds.path_.return_value = self._FAKE_RES_PATH
        mock_rasds.ResourceSubType = resource_sub_type
        mock_rasds.Address = self._FAKE_ADDRESS
        mock_vm_settings.associators.return_value = [mock_rasds]
        mock_vm.associators.return_value = [mock_vm_settings]

    def _prepare_resources(self, mock_path, mock_subtype, mock_vm_settings):
        mock_rasds = mock_vm_settings.associators.return_value[0]
        mock_rasds.path_.return_value = mock_path
        mock_rasds.ResourceSubType = mock_subtype
        return mock_rasds

    @mock.patch.object(vmutils.VMUtils, 'get_free_controller_slot')
    @mock.patch.object(vmutils.VMUtils, '_get_vm_scsi_controller')
    def test_attach_scsi_drive(self, mock_get_vm_scsi_controller,
                               mock_get_free_controller_slot):
        mock_vm = self._lookup_vm()
        mock_get_vm_scsi_controller.return_value = self._FAKE_CTRL_PATH
        mock_get_free_controller_slot.return_value = self._FAKE_DRIVE_ADDR

        with mock.patch.object(self._vmutils,
                               'attach_drive') as mock_attach_drive:
            self._vmutils.attach_scsi_drive(mock_vm, self._FAKE_PATH,
                                            constants.DISK)

            mock_get_vm_scsi_controller.assert_called_once_with(mock_vm)
            mock_get_free_controller_slot.assert_called_once_with(
                self._FAKE_CTRL_PATH)
            mock_attach_drive.assert_called_once_with(
                mock_vm, self._FAKE_PATH, self._FAKE_CTRL_PATH,
                self._FAKE_DRIVE_ADDR, constants.DISK)

    @mock.patch.object(vmutils.VMUtils, '_get_new_resource_setting_data')
    @mock.patch.object(vmutils.VMUtils, '_get_vm_ide_controller')
    def test_attach_ide_drive(self, mock_get_ide_ctrl, mock_get_new_rsd):
        mock_vm = self._lookup_vm()
        mock_rsd = mock_get_new_rsd.return_value

        self._vmutils.attach_ide_drive(self._FAKE_VM_NAME,
                                       self._FAKE_CTRL_PATH,
                                       self._FAKE_CTRL_ADDR,
                                       self._FAKE_DRIVE_ADDR)

        self._vmutils._jobutils.add_virt_resource.assert_called_with(
            mock_rsd, mock_vm)

        mock_get_ide_ctrl.assert_called_with(mock_vm, self._FAKE_CTRL_ADDR)
        self.assertTrue(mock_get_new_rsd.called)

    @mock.patch.object(vmutils.VMUtils, '_get_new_resource_setting_data')
    def test_create_scsi_controller(self, mock_get_new_rsd):
        mock_vm = self._lookup_vm()

        self._vmutils.create_scsi_controller(self._FAKE_VM_NAME)

        self._vmutils._jobutils.add_virt_resource.assert_called_once_with(
            mock_get_new_rsd.return_value, mock_vm)

    @mock.patch.object(vmutils.VMUtils, '_get_new_resource_setting_data')
    def test_attach_volume_to_controller(self, mock_get_new_rsd):
        mock_vm = self._lookup_vm()

        self._vmutils.attach_volume_to_controller(
            self._FAKE_VM_NAME, self._FAKE_CTRL_PATH, self._FAKE_CTRL_ADDR,
            self._FAKE_MOUNTED_DISK_PATH)

        self._vmutils._jobutils.add_virt_resource.assert_called_once_with(
            mock_get_new_rsd.return_value, mock_vm)

    @mock.patch.object(vmutils.VMUtils, '_get_new_setting_data')
    def test_create_nic(self, mock_get_new_virt_res):
        mock_vm = self._lookup_vm()
        mock_nic = mock_get_new_virt_res.return_value

        self._vmutils.create_nic(
            self._FAKE_VM_NAME, self._FAKE_RES_NAME, self._FAKE_ADDRESS)

        self._vmutils._jobutils.add_virt_resource.assert_called_once_with(
            mock_nic, mock_vm)

    @mock.patch.object(vmutils.VMUtils, '_get_nic_data_by_name')
    def test_destroy_nic(self, mock_get_nic_data_by_name):
        mock_vm = self._lookup_vm()
        mock_nic_data = mock_get_nic_data_by_name.return_value

        self._vmutils.destroy_nic(self._FAKE_VM_NAME,
                                  mock.sentinel.FAKE_NIC_NAME)

        self._vmutils._jobutils.remove_virt_resource.assert_called_once_with(
            mock_nic_data, mock_vm)

    def test_set_vm_state(self):
        mock_vm = self._lookup_vm()
        mock_vm.RequestStateChange.return_value = (
            self._FAKE_JOB_PATH, self._FAKE_RET_VAL)

        self._vmutils.set_vm_state(self._FAKE_VM_NAME,
                                   constants.HYPERV_VM_STATE_ENABLED)
        mock_vm.RequestStateChange.assert_called_with(
            constants.HYPERV_VM_STATE_ENABLED)

    def test_destroy_vm(self):
        self._lookup_vm()

        mock_svc = self._vmutils._conn.Msvm_VirtualSystemManagementService()[0]
        getattr(mock_svc, self._DESTROY_SYSTEM).return_value = (
            self._FAKE_JOB_PATH, self._FAKE_RET_VAL)

        self._vmutils.destroy_vm(self._FAKE_VM_NAME)

        getattr(mock_svc, self._DESTROY_SYSTEM).assert_called_with(
            self._FAKE_VM_PATH)

    def test_set_disk_host_resource(self):
        mock_vm = self._lookup_vm()
        mock_rasds = self._create_mock_disks()

        self._vmutils._get_vm_disks = mock.MagicMock(
            return_value=([mock_rasds[0]], [mock_rasds[1]]))
        self._vmutils._get_disk_resource_address = mock.MagicMock(
            return_value=self._FAKE_ADDRESS)

        self._vmutils.set_disk_host_resource(
            self._FAKE_VM_NAME,
            self._FAKE_CTRL_PATH,
            self._FAKE_ADDRESS,
            mock.sentinel.fake_new_mounted_disk_path)
        self._vmutils._get_disk_resource_address.assert_called_with(
            mock_rasds[0])
        self._vmutils._jobutils.modify_virt_resource.assert_called_once_with(
            mock_rasds[0], mock_vm)
        self.assertEqual(
            mock.sentinel.fake_new_mounted_disk_path,
            mock_rasds[0].HostResource[0])

    @mock.patch.object(vmutils, 'wmi', create=True)
    def test_take_vm_snapshot(self, mock_wmi):
        self._lookup_vm()

        mock_svc = self._get_snapshot_service()
        mock_svc.CreateSnapshot.return_value = (self._FAKE_JOB_PATH,
                                                mock.MagicMock(),
                                                self._FAKE_RET_VAL)

        self._vmutils.take_vm_snapshot(self._FAKE_VM_NAME)

        mock_svc.CreateSnapshot.assert_called_with(
            AffectedSystem=self._FAKE_VM_PATH,
            SnapshotType=self._vmutils._SNAPSHOT_FULL)

        self._vmutils._jobutils.check_ret_val.assert_called_once_with(
            self._FAKE_RET_VAL, self._FAKE_JOB_PATH)

    def test_remove_vm_snapshot(self):
        mock_svc = self._get_snapshot_service()
        getattr(mock_svc, self._DESTROY_SNAPSHOT).return_value = (
            self._FAKE_JOB_PATH, self._FAKE_RET_VAL)

        self._vmutils.remove_vm_snapshot(self._FAKE_SNAPSHOT_PATH)
        getattr(mock_svc, self._DESTROY_SNAPSHOT).assert_called_with(
            self._FAKE_SNAPSHOT_PATH)

    @mock.patch.object(vmutils.VMUtils, '_get_vm_disks')
    def test_enable_vm_metrics_collection(self, mock_get_vm_disks):
        self._lookup_vm()
        mock_svc = self._vmutils._conn.Msvm_MetricService()[0]

        metric_def = mock.MagicMock()
        mock_disk = mock.MagicMock()
        mock_disk.path_.return_value = self._FAKE_RES_PATH
        mock_get_vm_disks.return_value = ([mock_disk], [mock_disk])

        fake_metric_def_paths = ['fake_0', 'fake_0', None]
        fake_metric_resource_paths = [self._FAKE_VM_PATH,
                                      self._FAKE_VM_PATH,
                                      self._FAKE_RES_PATH]

        metric_def.path_.side_effect = fake_metric_def_paths
        self._vmutils._conn.CIM_BaseMetricDefinition.return_value = [
            metric_def]

        self._vmutils.enable_vm_metrics_collection(self._FAKE_VM_NAME)

        calls = [mock.call(Name=def_name)
                 for def_name in [self._vmutils._METRIC_AGGR_CPU_AVG,
                                  self._vmutils._METRIC_AGGR_MEMORY_AVG]]
        self._vmutils._conn.CIM_BaseMetricDefinition.assert_has_calls(calls)

        calls = []
        for i in range(len(fake_metric_def_paths)):
            calls.append(mock.call(
                Subject=fake_metric_resource_paths[i],
                Definition=fake_metric_def_paths[i],
                MetricCollectionEnabled=self._vmutils._METRIC_ENABLED))

        mock_svc.ControlMetrics.assert_has_calls(calls, any_order=True)

    def test_get_vm_dvd_disk_paths(self):
        mock_vm = self._lookup_vm()
        mock_sasd1 = mock.MagicMock(
            ResourceSubType=self._vmutils._DVD_DISK_RES_SUB_TYPE,
            HostResource=[mock.sentinel.FAKE_DVD_PATH1])
        mock_settings = mock.MagicMock()
        mock_settings.associators.return_value = [mock_sasd1]
        mock_vm.associators.return_value = [mock_settings]

        ret_val = self._vmutils.get_vm_dvd_disk_paths(self._FAKE_VM_NAME)
        self.assertEqual(mock.sentinel.FAKE_DVD_PATH1, ret_val[0])

    def test_detach_vm_disk(self):
        mock_vm = self._lookup_vm()
        mock_disk = self._prepare_mock_disk()

        self._vmutils.detach_vm_disk(self._FAKE_VM_NAME,
                                     self._FAKE_HOST_RESOURCE)
        self._vmutils._jobutils.remove_virt_resource.assert_called_once_with(
            mock_disk, mock_vm)

    def test_get_mounted_disk_resource_from_path(self):
        mock_disk_1 = mock.MagicMock()
        mock_disk_2 = mock.MagicMock()
        mock_disk_2.HostResource = [self._FAKE_MOUNTED_DISK_PATH]
        self._vmutils._conn.query.return_value = [mock_disk_1, mock_disk_2]

        physical_disk = self._vmutils._get_mounted_disk_resource_from_path(
            self._FAKE_MOUNTED_DISK_PATH, True)

        self.assertEqual(mock_disk_2, physical_disk)

    def test_get_controller_volume_paths(self):
        self._prepare_mock_disk()
        mock_disks = {self._FAKE_RES_PATH: self._FAKE_HOST_RESOURCE}
        disks = self._vmutils.get_controller_volume_paths(self._FAKE_RES_PATH)
        self.assertEqual(mock_disks, disks)

    def _prepare_mock_disk(self):
        mock_disk = mock.MagicMock()
        mock_disk.HostResource = [self._FAKE_HOST_RESOURCE]
        mock_disk.path.return_value.RelPath = self._FAKE_RES_PATH
        mock_disk.ResourceSubType = self._vmutils._HARD_DISK_RES_SUB_TYPE
        self._vmutils._conn.query.return_value = [mock_disk]

        return mock_disk

    def _get_snapshot_service(self):
        return self._vmutils._conn.Msvm_VirtualSystemSnapshotService()[0]

    def test_get_active_instances(self):
        fake_vm = mock.MagicMock()

        type(fake_vm).ElementName = mock.PropertyMock(
            side_effect=['active_vm', 'inactive_vm'])
        type(fake_vm).EnabledState = mock.PropertyMock(
            side_effect=[constants.HYPERV_VM_STATE_ENABLED,
                         constants.HYPERV_VM_STATE_DISABLED])
        self._vmutils.list_instances = mock.MagicMock(
            return_value=[mock.sentinel.fake_vm_name] * 2)
        self._vmutils._lookup_vm = mock.MagicMock(side_effect=[fake_vm] * 2)
        active_instances = self._vmutils.get_active_instances()

        self.assertEqual(['active_vm'], active_instances)

    def _test_get_vm_serial_port_connection(self, new_connection=None):
        old_serial_connection = 'old_serial_connection'

        mock_vm = self._lookup_vm()
        mock_vmsettings = [mock.MagicMock()]
        mock_vm.associators.return_value = mock_vmsettings

        fake_serial_port = mock.MagicMock()

        fake_serial_port.ResourceSubType = (
            self._vmutils._SERIAL_PORT_RES_SUB_TYPE)
        fake_serial_port.Connection = [old_serial_connection]
        mock_rasds = [fake_serial_port]
        mock_vmsettings[0].associators.return_value = mock_rasds
        fake_modify = self._vmutils._jobutils.modify_virt_resource

        ret_val = self._vmutils.get_vm_serial_port_connection(
            self._FAKE_VM_NAME, update_connection=new_connection)

        mock_vmsettings[0].associators.assert_called_once_with(
            wmi_result_class=self._vmutils._SERIAL_PORT_SETTING_DATA_CLASS)

        if new_connection:
            self.assertEqual(new_connection, ret_val)
            fake_modify.assert_called_once_with(fake_serial_port,
                                                mock_vm)
        else:
            self.assertEqual(old_serial_connection, ret_val)

    def test_set_vm_serial_port_connection(self):
        self._test_get_vm_serial_port_connection('new_serial_connection')

    def test_get_vm_serial_port_connection(self):
        self._test_get_vm_serial_port_connection()

    def test_list_instance_notes(self):
        vs = mock.MagicMock()
        attrs = {'ElementName': 'fake_name',
                 'Notes': ['4f54fb69-d3a2-45b7-bb9b-b6e6b3d893b3']}
        vs.configure_mock(**attrs)
        vs2 = mock.MagicMock(ElementName='fake_name2', Notes=None)
        self._vmutils._conn.Msvm_VirtualSystemSettingData.return_value = [vs,
                                                                          vs2]
        response = self._vmutils.list_instance_notes()

        self.assertEqual([(attrs['ElementName'], attrs['Notes'])], response)
        self._vmutils._conn.Msvm_VirtualSystemSettingData.assert_called_with(
            ['ElementName', 'Notes'],
            VirtualSystemType=self._vmutils._VIRTUAL_SYSTEM_TYPE_REALIZED)

    def test_modify_virtual_system(self):
        mock_vs_man_svc = mock.MagicMock()
        mock_vmsetting = mock.MagicMock()
        fake_path = 'fake path'
        fake_job_path = 'fake job path'
        fake_ret_val = 'fake return value'

        mock_vs_man_svc.ModifyVirtualSystem.return_value = (0, fake_job_path,
                                                            fake_ret_val)

        self._vmutils._modify_virtual_system(vs_man_svc=mock_vs_man_svc,
                                             vm_path=fake_path,
                                             vmsetting=mock_vmsetting)

        mock_vs_man_svc.ModifyVirtualSystem.assert_called_once_with(
            ComputerSystem=fake_path,
            SystemSettingData=mock_vmsetting.GetText_(1))
        self._vmutils._jobutils.check_ret_val.assert_called_once_with(
            fake_ret_val, fake_job_path)

    @mock.patch.object(vmutils.VMUtils, '_get_wmi_obj')
    def _test_create_vm_obj(self, mock_get_wmi_obj, vm_path,
                            dynamic_memory_ratio=1.0):
        mock_vs_man_svc = mock.MagicMock()
        mock_vs_data = mock.MagicMock()
        mock_job = mock.MagicMock()
        fake_job_path = 'fake job path'
        fake_ret_val = 'fake return value'
        fake_vm_name = 'fake_vm_name'
        _conn = self._vmutils._conn.Msvm_VirtualSystemSettingData

        self._vmutils._jobutils.check_ret_val.return_value = mock_job
        _conn.new.return_value = mock_vs_data
        mock_vs_man_svc.DefineSystem.return_value = (fake_job_path,
                                                     vm_path,
                                                     fake_ret_val)
        mock_job.associators.return_value = ['fake vm path']

        response = self._vmutils._create_vm_obj(
            vs_man_svc=mock_vs_man_svc,
            vm_name=fake_vm_name,
            vm_gen=constants.VM_GEN_2,
            notes='fake notes',
            dynamic_memory_ratio=dynamic_memory_ratio,
            instance_path=mock.sentinel.instance_path)

        if not vm_path:
            mock_job.associators.assert_called_once_with(
                self._vmutils._AFFECTED_JOB_ELEMENT_CLASS)

        _conn.new.assert_called_once_with()
        self.assertEqual(mock_vs_data.ElementName, fake_vm_name)
        mock_vs_man_svc.DefineSystem.assert_called_once_with(
            ResourceSettings=[], ReferenceConfiguration=None,
            SystemSettings=mock_vs_data.GetText_(1))
        self._vmutils._jobutils.check_ret_val.assert_called_once_with(
            fake_ret_val, fake_job_path)

        self.assertEqual(self._vmutils._VIRTUAL_SYSTEM_SUBTYPE_GEN2,
                         mock_vs_data.VirtualSystemSubType)
        self.assertFalse(mock_vs_data.SecureBootEnabled)

        if dynamic_memory_ratio > 1:
            self.assertFalse(mock_vs_data.VirtualNumaEnabled)

        mock_get_wmi_obj.assert_called_with('fake vm path')

        self.assertEqual(mock_vs_data.Notes, 'fake notes')
        self.assertEqual(mock.sentinel.instance_path,
                         mock_vs_data.ConfigurationDataRoot)
        self.assertEqual(mock.sentinel.instance_path, mock_vs_data.LogDataRoot)
        self.assertEqual(mock.sentinel.instance_path,
                         mock_vs_data.SnapshotDataRoot)
        self.assertEqual(mock.sentinel.instance_path,
                         mock_vs_data.SuspendDataRoot)
        self.assertEqual(mock.sentinel.instance_path,
                         mock_vs_data.SwapFileDataRoot)
        self.assertEqual(response, mock_get_wmi_obj())

    def test_create_vm_obj(self):
        self._test_create_vm_obj(vm_path='fake vm path')

    def test_create_vm_obj_no_vm_path(self):
        self._test_create_vm_obj(vm_path=None)

    def test_create_vm_obj_dynamic_memory(self):
        self._test_create_vm_obj(vm_path=None, dynamic_memory_ratio=1.1)

    def test_list_instances(self):
        vs = mock.MagicMock()
        attrs = {'ElementName': 'fake_name'}
        vs.configure_mock(**attrs)
        self._vmutils._conn.Msvm_VirtualSystemSettingData.return_value = [vs]
        response = self._vmutils.list_instances()

        self.assertEqual([(attrs['ElementName'])], response)
        self._vmutils._conn.Msvm_VirtualSystemSettingData.assert_called_with(
            ['ElementName'],
            VirtualSystemType=self._vmutils._VIRTUAL_SYSTEM_TYPE_REALIZED)

    def test_get_attached_disks(self):
        mock_scsi_ctrl_path = mock.MagicMock()
        expected_query = ("SELECT * FROM %(class_name)s "
                          "WHERE (ResourceSubType='%(res_sub_type)s' OR "
                          "ResourceSubType='%(res_sub_type_virt)s' OR "
                          "ResourceSubType='%(res_sub_type_dvd)s') AND "
                          "Parent = '%(parent)s'" %
                          {"class_name":
                           self._vmutils._RESOURCE_ALLOC_SETTING_DATA_CLASS,
                           "res_sub_type":
                           self._vmutils._PHYS_DISK_RES_SUB_TYPE,
                           "res_sub_type_virt":
                           self._vmutils._DISK_DRIVE_RES_SUB_TYPE,
                           "res_sub_type_dvd":
                           self._vmutils._DVD_DRIVE_RES_SUB_TYPE,
                           "parent": mock_scsi_ctrl_path.replace("'", "''")})
        expected_disks = self._vmutils._conn.query.return_value

        ret_disks = self._vmutils.get_attached_disks(mock_scsi_ctrl_path)

        self._vmutils._conn.query.assert_called_once_with(expected_query)
        self.assertEqual(expected_disks, ret_disks)

    def _get_fake_instance_notes(self):
        return [self._FAKE_VM_UUID]

    def test_instance_notes(self):
        self._lookup_vm()
        mock_vm_settings = mock.Mock()
        mock_vm_settings.Notes = self._get_fake_instance_notes()
        self._vmutils._get_vm_setting_data = mock.Mock(
            return_value=mock_vm_settings)

        notes = self._vmutils._get_instance_notes(mock.sentinel.vm_name)

        self.assertEqual(notes[0], self._FAKE_VM_UUID)

    def test_get_event_wql_query(self):
        cls = self._vmutils._COMPUTER_SYSTEM_CLASS
        field = self._vmutils._VM_ENABLED_STATE_PROP
        timeframe = 10
        filtered_states = [constants.HYPERV_VM_STATE_ENABLED,
                           constants.HYPERV_VM_STATE_DISABLED]

        expected_checks = ' OR '.join(
            ["TargetInstance.%s = '%s'" % (field, state)
             for state in filtered_states])
        expected_query = (
            "SELECT %(field)s, TargetInstance "
            "FROM __InstanceModificationEvent "
            "WITHIN %(timeframe)s "
            "WHERE TargetInstance ISA '%(class)s' "
            "AND TargetInstance.%(field)s != "
            "PreviousInstance.%(field)s "
            "AND (%(checks)s)" %
                {'class': cls,
                 'field': field,
                 'timeframe': timeframe,
                 'checks': expected_checks})

        query = self._vmutils._get_event_wql_query(
            cls=cls, field=field, timeframe=timeframe,
            filtered_states=filtered_states)
        self.assertEqual(expected_query, query)

    def test_get_vm_power_state_change_listener(self):
        with mock.patch.object(self._vmutils,
                               '_get_event_wql_query') as mock_get_query:
            listener = self._vmutils.get_vm_power_state_change_listener(
                mock.sentinel.timeframe,
                mock.sentinel.filtered_states)

            mock_get_query.assert_called_once_with(
                cls=self._vmutils._COMPUTER_SYSTEM_CLASS,
                field=self._vmutils._VM_ENABLED_STATE_PROP,
                timeframe=mock.sentinel.timeframe,
                filtered_states=mock.sentinel.filtered_states)
            watcher = self._vmutils._conn.Msvm_ComputerSystem.watch_for
            watcher.assert_called_once_with(
                raw_wql=mock_get_query.return_value,
                fields=[self._vmutils._VM_ENABLED_STATE_PROP])

            self.assertEqual(watcher.return_value, listener)

    @mock.patch.object(vmutils.VMUtils, '_get_vm_setting_data')
    def _test_get_vm_generation(self, vm_gen, mock_get_vm_setting_data):
        self._lookup_vm()
        vm_gen_string = "Microsoft:Hyper-V:SubType:" + str(vm_gen)
        mock_vssd = mock.MagicMock(VirtualSystemSubType=vm_gen_string)
        mock_get_vm_setting_data.return_value = mock_vssd

        ret = self._vmutils.get_vm_generation(mock.sentinel.FAKE_VM_NAME)

        self.assertEqual(vm_gen, ret)

    def test_get_vm_generation_gen1(self):
        self._test_get_vm_generation(constants.VM_GEN_1)

    def test_get_vm_generation_gen2(self):
        self._test_get_vm_generation(constants.VM_GEN_2)

    def test_stop_vm_jobs(self):
        mock_vm = self._lookup_vm()

        self._vmutils.stop_vm_jobs(mock.sentinel.vm_name)

        self._vmutils._jobutils.stop_jobs.assert_called_once_with(mock_vm)
