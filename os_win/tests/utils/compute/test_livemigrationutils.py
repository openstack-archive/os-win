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

import ddt

import mock
import platform

from os_win import exceptions
from os_win.tests import test_base
from os_win.utils import _wqlutils
from os_win.utils.compute import livemigrationutils
from os_win.utils.compute import vmutils


@ddt.ddt
class LiveMigrationUtilsTestCase(test_base.OsWinBaseTestCase):
    """Unit tests for the Hyper-V LiveMigrationUtils class."""

    _FAKE_VM_NAME = 'fake_vm_name'
    _FAKE_RET_VAL = 0

    _RESOURCE_TYPE_VHD = 31
    _RESOURCE_TYPE_DISK = 17
    _RESOURCE_SUB_TYPE_VHD = 'Microsoft:Hyper-V:Virtual Hard Disk'
    _RESOURCE_SUB_TYPE_DISK = 'Microsoft:Hyper-V:Physical Disk Drive'

    def setUp(self):
        super(LiveMigrationUtilsTestCase, self).setUp()
        self.liveutils = livemigrationutils.LiveMigrationUtils()
        self._conn = mock.MagicMock()
        self.liveutils._conn_attr = self._conn
        self.liveutils._vmutils = mock.MagicMock()
        self.liveutils._iscsi_initiator = mock.MagicMock()
        self.liveutils._jobutils = mock.Mock()

        self.liveutils._get_conn_v2 = mock.MagicMock(return_value=self._conn)
        self.liveutils._conn_v2 = self._conn

    def test_check_live_migration_config(self):
        mock_migr_svc = (
            self._conn.Msvm_VirtualSystemMigrationService.return_value[0])
        conn_vsmssd = self._conn.Msvm_VirtualSystemMigrationServiceSettingData

        vsmssd = mock.MagicMock()
        vsmssd.EnableVirtualSystemMigration = True
        conn_vsmssd.return_value = [vsmssd]
        mock_migr_svc.MigrationServiceListenerIPAdressList.return_value = [
            mock.sentinel.FAKE_HOST]

        self.liveutils.check_live_migration_config()
        conn_vsmssd.assert_called_once_with()
        self._conn.Msvm_VirtualSystemMigrationService.assert_called_once_with()

    def test_get_vm(self):
        expected_vm = mock.MagicMock()
        mock_conn_v2 = mock.MagicMock()
        mock_conn_v2.Msvm_ComputerSystem.return_value = [expected_vm]

        found_vm = self.liveutils._get_vm(mock_conn_v2, self._FAKE_VM_NAME)

        self.assertEqual(expected_vm, found_vm)

    def test_get_vm_duplicate(self):
        mock_vm = mock.MagicMock()
        mock_conn_v2 = mock.MagicMock()
        mock_conn_v2.Msvm_ComputerSystem.return_value = [mock_vm, mock_vm]

        self.assertRaises(exceptions.HyperVException, self.liveutils._get_vm,
                          mock_conn_v2, self._FAKE_VM_NAME)

    def test_get_vm_not_found(self):
        mock_conn_v2 = mock.MagicMock()
        mock_conn_v2.Msvm_ComputerSystem.return_value = []

        self.assertRaises(exceptions.HyperVVMNotFoundException,
                          self.liveutils._get_vm,
                          mock_conn_v2, self._FAKE_VM_NAME)

    def test_destroy_planned_vm(self):
        mock_planned_vm = mock.MagicMock()
        mock_planned_vm.path_.return_value = mock.sentinel.planned_vm_path
        mock_vs_man_svc = self.liveutils._vs_man_svc
        mock_vs_man_svc.DestroySystem.return_value = (
            mock.sentinel.job_path, mock.sentinel.ret_val)

        self.liveutils._destroy_planned_vm(mock_planned_vm)

        mock_vs_man_svc.DestroySystem.assert_called_once_with(
            mock.sentinel.planned_vm_path)
        self.liveutils._jobutils.check_ret_val.assert_called_once_with(
            mock.sentinel.ret_val,
            mock.sentinel.job_path)

    @ddt.data({'planned_vm': None}, {'planned_vm': mock.sentinel.planned_vm})
    @ddt.unpack
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_destroy_planned_vm')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_get_planned_vm')
    def test_destroy_existing_planned_vm(self, mock_get_planned_vm,
                                         mock_destroy_planned_vm, planned_vm):
        mock_get_planned_vm.return_value = planned_vm

        self.liveutils.destroy_existing_planned_vm(mock.sentinel.vm_name)

        mock_get_planned_vm.assert_called_once_with(
            mock.sentinel.vm_name, self._conn)
        if planned_vm:
            mock_destroy_planned_vm.assert_called_once_with(planned_vm)
        else:
            self.assertFalse(mock_destroy_planned_vm.called)

    def test_create_planned_vm_helper(self):
        mock_vm = mock.MagicMock()
        mock_v2 = mock.MagicMock()
        mock_vsmsd_cls = mock_v2.Msvm_VirtualSystemMigrationSettingData
        mock_vsmsd = mock_vsmsd_cls.return_value[0]
        self._conn.Msvm_PlannedComputerSystem.return_value = [mock_vm]

        migr_svc = mock_v2.Msvm_VirtualSystemMigrationService()[0]
        migr_svc.MigrateVirtualSystemToHost.return_value = (
            self._FAKE_RET_VAL, mock.sentinel.FAKE_JOB_PATH)

        resulted_vm = self.liveutils._create_planned_vm(
            self._conn, mock_v2, mock_vm, [mock.sentinel.FAKE_REMOTE_IP_ADDR],
            mock.sentinel.FAKE_HOST)

        self.assertEqual(mock_vm, resulted_vm)

        mock_vsmsd_cls.assert_called_once_with(
            MigrationType=self.liveutils._MIGRATION_TYPE_STAGED)
        migr_svc.MigrateVirtualSystemToHost.assert_called_once_with(
            ComputerSystem=mock_vm.path_.return_value,
            DestinationHost=mock.sentinel.FAKE_HOST,
            MigrationSettingData=mock_vsmsd.GetText_.return_value)
        self.liveutils._jobutils.check_ret_val.assert_called_once_with(
            mock.sentinel.FAKE_JOB_PATH,
            self._FAKE_RET_VAL)

    def test_get_physical_disk_paths(self):
        ide_path = {mock.sentinel.IDE_PATH: mock.sentinel.IDE_HOST_RESOURCE}
        scsi_path = {mock.sentinel.SCSI_PATH: mock.sentinel.SCSI_HOST_RESOURCE}
        ide_ctrl = self.liveutils._vmutils.get_vm_ide_controller.return_value
        scsi_ctrl = self.liveutils._vmutils.get_vm_scsi_controller.return_value
        mock_get_controller_paths = (
            self.liveutils._vmutils.get_controller_volume_paths)

        mock_get_controller_paths.side_effect = [ide_path, scsi_path]

        result = self.liveutils._get_physical_disk_paths(mock.sentinel.VM_NAME)

        expected = dict(ide_path)
        expected.update(scsi_path)
        self.assertDictContainsSubset(expected, result)
        calls = [mock.call(ide_ctrl), mock.call(scsi_ctrl)]
        mock_get_controller_paths.assert_has_calls(calls)

    def test_get_physical_disk_paths_no_ide(self):
        scsi_path = {mock.sentinel.SCSI_PATH: mock.sentinel.SCSI_HOST_RESOURCE}
        scsi_ctrl = self.liveutils._vmutils.get_vm_scsi_controller.return_value
        mock_get_controller_paths = (
            self.liveutils._vmutils.get_controller_volume_paths)

        self.liveutils._vmutils.get_vm_ide_controller.return_value = None
        mock_get_controller_paths.return_value = scsi_path

        result = self.liveutils._get_physical_disk_paths(mock.sentinel.VM_NAME)

        self.assertEqual(scsi_path, result)
        mock_get_controller_paths.assert_called_once_with(scsi_ctrl)

    @mock.patch.object(livemigrationutils.iscsi_wmi_utils,
                       'ISCSIInitiatorWMIUtils')
    def test_get_remote_disk_data(self, mock_iscsi_initiator_class):
        m_remote_iscsi_init = mock_iscsi_initiator_class.return_value
        m_local_iscsi_init = self.liveutils._iscsi_initiator

        mock_vm_utils = mock.MagicMock()
        disk_paths = {
            mock.sentinel.FAKE_RASD_PATH: mock.sentinel.FAKE_DISK_PATH}
        m_local_iscsi_init.get_target_from_disk_path.return_value = (
            mock.sentinel.FAKE_IQN, mock.sentinel.FAKE_LUN)
        m_remote_iscsi_init.get_device_number_for_target.return_value = (
            mock.sentinel.FAKE_DEV_NUM)
        mock_vm_utils.get_mounted_disk_by_drive_number.return_value = (
            mock.sentinel.FAKE_DISK_PATH)

        disk_paths = self.liveutils._get_remote_disk_data(
            mock_vm_utils, disk_paths, mock.sentinel.FAKE_HOST)

        m_local_iscsi_init.get_target_from_disk_path.assert_called_with(
            mock.sentinel.FAKE_DISK_PATH)
        m_remote_iscsi_init.get_device_number_for_target.assert_called_with(
            mock.sentinel.FAKE_IQN, mock.sentinel.FAKE_LUN)
        mock_vm_utils.get_mounted_disk_by_drive_number.assert_called_once_with(
            mock.sentinel.FAKE_DEV_NUM)

        self.assertEqual(
            {mock.sentinel.FAKE_RASD_PATH: mock.sentinel.FAKE_DISK_PATH},
            disk_paths)

    def test_get_disk_data(self):
        mock_vmutils_remote = mock.MagicMock()
        mock_disk = mock.MagicMock()
        mock_disk_path_mapping = {
            mock.sentinel.serial: mock.sentinel.disk_path}

        mock_disk.path.return_value.RelPath = mock.sentinel.rel_path
        mock_vmutils_remote.get_vm_disks.return_value = [
            None, [mock_disk]]
        mock_disk.ElementName = mock.sentinel.serial

        resulted_disk_paths = self.liveutils._get_disk_data(
            self._FAKE_VM_NAME, mock_vmutils_remote, mock_disk_path_mapping)

        mock_vmutils_remote.get_vm_disks.assert_called_once_with(
            self._FAKE_VM_NAME)
        mock_disk.path.assert_called_once_with()
        expected_disk_paths = {mock.sentinel.rel_path: mock.sentinel.disk_path}
        self.assertEqual(expected_disk_paths, resulted_disk_paths)

    @mock.patch.object(_wqlutils, 'get_element_associated_class')
    def test_update_planned_vm_disk_resources(self,
                                              mock_get_elem_associated_class):
        self._prepare_vm_mocks(self._RESOURCE_TYPE_DISK,
                               self._RESOURCE_SUB_TYPE_DISK,
                               mock_get_elem_associated_class)
        mock_vm = mock.Mock(Name='fake_name')
        sasd = mock_get_elem_associated_class.return_value[0]

        mock_vsmsvc = self._conn.Msvm_VirtualSystemManagementService()[0]

        self.liveutils._update_planned_vm_disk_resources(
            self._conn, mock_vm, mock.sentinel.FAKE_VM_NAME,
            {sasd.path.return_value.RelPath: mock.sentinel.FAKE_RASD_PATH})

        mock_vsmsvc.ModifyResourceSettings.assert_called_once_with(
            ResourceSettings=[sasd.GetText_.return_value])
        mock_get_elem_associated_class.assert_called_once_with(
            self._conn, self.liveutils._CIM_RES_ALLOC_SETTING_DATA_CLASS,
            element_uuid=mock_vm.Name)

    @mock.patch.object(_wqlutils, 'get_element_associated_class')
    def test_get_vhd_setting_data(self, mock_get_elem_associated_class):
        self._prepare_vm_mocks(self._RESOURCE_TYPE_VHD,
                               self._RESOURCE_SUB_TYPE_VHD,
                               mock_get_elem_associated_class)
        mock_vm = mock.Mock(Name='fake_vm_name')
        mock_sasd = mock_get_elem_associated_class.return_value[0]

        vhd_sds = self.liveutils._get_vhd_setting_data(mock_vm)
        self.assertEqual([mock_sasd.GetText_.return_value], vhd_sds)
        mock_get_elem_associated_class.assert_called_once_with(
            self._conn, self.liveutils._STORAGE_ALLOC_SETTING_DATA_CLASS,
            element_uuid=mock_vm.Name)

    def test_live_migrate_vm_helper(self):
        mock_conn_local = mock.MagicMock()
        mock_vm = mock.MagicMock()
        mock_vsmsd_cls = (
            mock_conn_local.Msvm_VirtualSystemMigrationSettingData)
        mock_vsmsd = mock_vsmsd_cls.return_value[0]

        mock_vsmsvc = mock_conn_local.Msvm_VirtualSystemMigrationService()[0]
        mock_vsmsvc.MigrateVirtualSystemToHost.return_value = (
            self._FAKE_RET_VAL, mock.sentinel.FAKE_JOB_PATH)

        self.liveutils._live_migrate_vm(
            mock_conn_local, mock_vm, None,
            [mock.sentinel.FAKE_REMOTE_IP_ADDR],
            mock.sentinel.FAKE_RASD_PATH, mock.sentinel.FAKE_HOST,
            mock.sentinel.migration_type)

        mock_vsmsd_cls.assert_called_once_with(
            MigrationType=mock.sentinel.migration_type)
        mock_vsmsvc.MigrateVirtualSystemToHost.assert_called_once_with(
            ComputerSystem=mock_vm.path_.return_value,
            DestinationHost=mock.sentinel.FAKE_HOST,
            MigrationSettingData=mock_vsmsd.GetText_.return_value,
            NewResourceSettingData=mock.sentinel.FAKE_RASD_PATH)

    @ddt.data(True, False)
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_get_planned_vm')
    @mock.patch.object(livemigrationutils, 'vmutils')
    def test_live_migrate_no_planned_vm(self, migrate_disks, mock_vm_utils,
                                        mock_get_planned_vm):
        mock_vm_utils_remote = mock_vm_utils.VMUtils.return_value
        mock_vm = self._get_vm()

        mock_migr_svc = self._conn.Msvm_VirtualSystemMigrationService()[0]
        mock_migr_svc.MigrationServiceListenerIPAddressList = [
            mock.sentinel.FAKE_REMOTE_IP_ADDR]

        # patches, call and assertions.
        with mock.patch.multiple(
                self.liveutils,
                _get_physical_disk_paths=mock.DEFAULT,
                _get_remote_disk_data=mock.DEFAULT,
                _create_planned_vm=mock.DEFAULT,
                _update_planned_vm_disk_resources=mock.DEFAULT,
                _get_vhd_setting_data=mock.DEFAULT,
                _live_migrate_vm=mock.DEFAULT):

            mock_get_planned_vm.return_value = None
            disk_paths = {
                mock.sentinel.FAKE_IDE_PATH: mock.sentinel.FAKE_SASD_RESOURCE}
            self.liveutils._get_physical_disk_paths.return_value = disk_paths
            mock_disk_paths = [mock.sentinel.FAKE_DISK_PATH]
            self.liveutils._get_remote_disk_data.return_value = (
                mock_disk_paths)
            self.liveutils._create_planned_vm.return_value = mock_vm

            self.liveutils.live_migrate_vm(mock.sentinel.vm_name,
                                           mock.sentinel.FAKE_HOST,
                                           migrate_disks=migrate_disks)
            mock_get_planned_vm.assert_called_once_with(
                mock.sentinel.vm_name, self._conn)
            self.liveutils._get_remote_disk_data.assert_called_once_with(
                mock_vm_utils_remote, disk_paths, mock.sentinel.FAKE_HOST)
            self.liveutils._create_planned_vm.assert_called_once_with(
                self._conn, self._conn, mock_vm,
                [mock.sentinel.FAKE_REMOTE_IP_ADDR], mock.sentinel.FAKE_HOST)
            mocked_method = self.liveutils._update_planned_vm_disk_resources
            mocked_method.assert_called_once_with(
                self._conn, mock_vm, mock.sentinel.vm_name,
                mock_disk_paths)

            if migrate_disks:
                expected_migr_type = (
                    self.liveutils._MIGRATION_TYPE_VIRTUAL_SYSTEM_AND_STORAGE)
                exp_new_rsd = self.liveutils._get_vhd_setting_data.return_value
            else:
                expected_migr_type = (
                    self.liveutils._MIGRATION_TYPE_VIRTUAL_SYSTEM)
                exp_new_rsd = None

            self.liveutils._live_migrate_vm.assert_called_once_with(
                self._conn, mock_vm, mock_vm,
                [mock.sentinel.FAKE_REMOTE_IP_ADDR],
                exp_new_rsd,
                mock.sentinel.FAKE_HOST,
                expected_migr_type)

    @mock.patch.object(
        livemigrationutils.LiveMigrationUtils, '_get_planned_vm')
    def test_live_migrate_single_planned_vm(self, mock_get_planned_vm):
        mock_vm = self._get_vm()

        mock_migr_svc = self._conn.Msvm_VirtualSystemMigrationService()[0]
        mock_migr_svc.MigrationServiceListenerIPAddressList = [
            mock.sentinel.FAKE_REMOTE_IP_ADDR]

        # patches, call and assertions.
        with mock.patch.multiple(
                self.liveutils,
                _get_vhd_setting_data=mock.DEFAULT,
                _live_migrate_vm=mock.DEFAULT):

            mock_get_planned_vm.return_value = mock_vm
            self.liveutils.live_migrate_vm(mock.sentinel.vm_name,
                                           mock.sentinel.FAKE_HOST)
            self.liveutils._live_migrate_vm.assert_called_once_with(
                self._conn, mock_vm, mock_vm,
                [mock.sentinel.FAKE_REMOTE_IP_ADDR],
                self.liveutils._get_vhd_setting_data.return_value,
                mock.sentinel.FAKE_HOST,
                self.liveutils._MIGRATION_TYPE_VIRTUAL_SYSTEM_AND_STORAGE)
            mock_get_planned_vm.assert_called_once_with(
                mock.sentinel.vm_name, self._conn)

    @mock.patch.object(vmutils, 'VMUtils')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils, '_get_vm')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_get_ip_address_list')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_update_planned_vm_disk_resources')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_create_planned_vm')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       'destroy_existing_planned_vm')
    @mock.patch.object(livemigrationutils.LiveMigrationUtils,
                       '_get_disk_data')
    def test_create_planned_vm(self, mock_get_disk_data,
                               mock_destroy_existing_planned_vm,
                               mock_create_planned_vm,
                               mock_update_planned_vm_disk_resources,
                               mock_get_ip_address_list, mock_get_vm,
                               mock_cls_vmutils):
        dest_host = platform.node()
        mock_vm = mock.MagicMock()
        mock_get_vm.return_value = mock_vm
        mock_conn_v2 = mock.MagicMock()
        self.liveutils._get_conn_v2.return_value = mock_conn_v2

        mock_get_disk_data.return_value = mock.sentinel.disk_data
        mock_get_ip_address_list.return_value = mock.sentinel.ip_address_list

        mock_vsmsvc = self._conn.Msvm_VirtualSystemManagementService()[0]
        mock_vsmsvc.ModifyResourceSettings.return_value = (
            mock.sentinel.res_setting,
            mock.sentinel.job_path,
            self._FAKE_RET_VAL)

        self.liveutils.create_planned_vm(mock.sentinel.vm_name,
                                         mock.sentinel.host,
                                         mock.sentinel.disk_path_mapping)

        mock_destroy_existing_planned_vm.assert_called_once_with(
            mock.sentinel.vm_name)
        mock_get_ip_address_list.assert_called_once_with(self._conn, dest_host)
        mock_get_disk_data.assert_called_once_with(
            mock.sentinel.vm_name,
            mock_cls_vmutils.return_value,
            mock.sentinel.disk_path_mapping)
        mock_create_planned_vm.assert_called_once_with(
            self._conn, mock_conn_v2, mock_vm,
            mock.sentinel.ip_address_list, dest_host)
        mock_update_planned_vm_disk_resources.assert_called_once_with(
            self._conn, mock_create_planned_vm.return_value,
            mock.sentinel.vm_name, mock.sentinel.disk_data)

    def _prepare_vm_mocks(self, resource_type, resource_sub_type,
                          mock_get_elem_associated_class):
        mock_vm_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        vm = self._get_vm()
        self._conn.Msvm_PlannedComputerSystem.return_value = [vm]
        mock_vm_svc.DestroySystem.return_value = (mock.sentinel.FAKE_JOB_PATH,
                                                  self._FAKE_RET_VAL)
        mock_vm_svc.ModifyResourceSettings.return_value = (
            None, mock.sentinel.FAKE_JOB_PATH, self._FAKE_RET_VAL)

        sasd = mock.MagicMock()
        other_sasd = mock.MagicMock()
        sasd.ResourceType = resource_type
        sasd.ResourceSubType = resource_sub_type
        sasd.HostResource = [mock.sentinel.FAKE_SASD_RESOURCE]
        sasd.path.return_value.RelPath = mock.sentinel.FAKE_DISK_PATH

        mock_get_elem_associated_class.return_value = [sasd, other_sasd]

    def _get_vm(self):
        mock_vm = mock.MagicMock()
        self._conn.Msvm_ComputerSystem.return_value = [mock_vm]
        mock_vm.path_.return_value = mock.sentinel.FAKE_VM_PATH
        mock_vm.Name = self._FAKE_VM_NAME
        return mock_vm
