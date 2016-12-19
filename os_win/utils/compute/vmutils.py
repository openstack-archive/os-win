# Copyright (c) 2010 Cloud.com, Inc
# Copyright 2012 Cloudbase Solutions Srl / Pedro Navarro Perez
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

"""
Utility class for VM related operations.
Based on the "root/virtualization/v2" namespace available starting with
Hyper-V Server / Windows Server 2012.
"""

import functools
import time
import uuid

from eventlet import patcher
from eventlet import tpool
from oslo_log import log as logging
from oslo_utils import uuidutils
import six
from six.moves import range  # noqa

from os_win._i18n import _, _LE, _LW
from os_win import _utils
from os_win import constants
from os_win import exceptions
from os_win.utils import _wqlutils
from os_win.utils import baseutils
from os_win.utils import jobutils
from os_win.utils import pathutils

LOG = logging.getLogger(__name__)


class VMUtils(baseutils.BaseUtilsVirt):

    # These constants can be overridden by inherited classes
    _PHYS_DISK_RES_SUB_TYPE = 'Microsoft:Hyper-V:Physical Disk Drive'
    _DISK_DRIVE_RES_SUB_TYPE = 'Microsoft:Hyper-V:Synthetic Disk Drive'
    _DVD_DRIVE_RES_SUB_TYPE = 'Microsoft:Hyper-V:Synthetic DVD Drive'
    _HARD_DISK_RES_SUB_TYPE = 'Microsoft:Hyper-V:Virtual Hard Disk'
    _DVD_DISK_RES_SUB_TYPE = 'Microsoft:Hyper-V:Virtual CD/DVD Disk'
    _IDE_CTRL_RES_SUB_TYPE = 'Microsoft:Hyper-V:Emulated IDE Controller'
    _SCSI_CTRL_RES_SUB_TYPE = 'Microsoft:Hyper-V:Synthetic SCSI Controller'
    _SERIAL_PORT_RES_SUB_TYPE = 'Microsoft:Hyper-V:Serial Port'

    _SETTINGS_DEFINE_STATE_CLASS = 'Msvm_SettingsDefineState'
    _VIRTUAL_SYSTEM_SETTING_DATA_CLASS = 'Msvm_VirtualSystemSettingData'
    _RESOURCE_ALLOC_SETTING_DATA_CLASS = 'Msvm_ResourceAllocationSettingData'
    _PROCESSOR_SETTING_DATA_CLASS = 'Msvm_ProcessorSettingData'
    _MEMORY_SETTING_DATA_CLASS = 'Msvm_MemorySettingData'
    _SERIAL_PORT_SETTING_DATA_CLASS = _RESOURCE_ALLOC_SETTING_DATA_CLASS
    _STORAGE_ALLOC_SETTING_DATA_CLASS = 'Msvm_StorageAllocationSettingData'
    _SYNTHETIC_ETHERNET_PORT_SETTING_DATA_CLASS = (
        'Msvm_SyntheticEthernetPortSettingData')
    _AFFECTED_JOB_ELEMENT_CLASS = "Msvm_AffectedJobElement"
    _CIM_RES_ALLOC_SETTING_DATA_CLASS = 'Cim_ResourceAllocationSettingData'
    _COMPUTER_SYSTEM_CLASS = "Msvm_ComputerSystem"
    _LOGICAL_IDENTITY_CLASS = 'Msvm_LogicalIdentity'

    _S3_DISP_CTRL_RES_SUB_TYPE = 'Microsoft:Hyper-V:S3 Display Controller'
    _SYNTH_DISP_CTRL_RES_SUB_TYPE = ('Microsoft:Hyper-V:Synthetic Display '
                                     'Controller')
    _SYNTH_3D_DISP_CTRL_RES_SUB_TYPE = ('Microsoft:Hyper-V:Synthetic 3D '
                                        'Display Controller')
    _SYNTH_3D_DISP_ALLOCATION_SETTING_DATA_CLASS = (
        'Msvm_Synthetic3DDisplayControllerSettingData')

    _VIRTUAL_SYSTEM_SUBTYPE = 'VirtualSystemSubType'
    _VIRTUAL_SYSTEM_TYPE_REALIZED = 'Microsoft:Hyper-V:System:Realized'
    _VIRTUAL_SYSTEM_TYPE_PLANNED = 'Microsoft:Hyper-V:System:Planned'
    _VIRTUAL_SYSTEM_SUBTYPE_GEN2 = 'Microsoft:Hyper-V:SubType:2'

    _SNAPSHOT_FULL = 2

    _VM_ENABLED_STATE_PROP = "EnabledState"

    _SHUTDOWN_COMPONENT = "Msvm_ShutdownComponent"
    _VIRTUAL_SYSTEM_CURRENT_SETTINGS = 3
    _AUTOMATIC_STARTUP_ACTION_NONE = 2

    _remote_fx_res_map = {
        constants.REMOTEFX_MAX_RES_1024x768: 0,
        constants.REMOTEFX_MAX_RES_1280x1024: 1,
        constants.REMOTEFX_MAX_RES_1600x1200: 2,
        constants.REMOTEFX_MAX_RES_1920x1200: 3,
        constants.REMOTEFX_MAX_RES_2560x1600: 4
    }

    _remotefx_max_monitors_map = {
        # defines the maximum number of monitors for a given
        # resolution
        constants.REMOTEFX_MAX_RES_1024x768: 4,
        constants.REMOTEFX_MAX_RES_1280x1024: 4,
        constants.REMOTEFX_MAX_RES_1600x1200: 3,
        constants.REMOTEFX_MAX_RES_1920x1200: 2,
        constants.REMOTEFX_MAX_RES_2560x1600: 1
    }

    _DISP_CTRL_ADDRESS_DX_11 = "02C1,00000000,01"

    _vm_power_states_map = {constants.HYPERV_VM_STATE_ENABLED: 2,
                            constants.HYPERV_VM_STATE_DISABLED: 3,
                            constants.HYPERV_VM_STATE_SHUTTING_DOWN: 4,
                            constants.HYPERV_VM_STATE_REBOOT: 11,
                            constants.HYPERV_VM_STATE_PAUSED: 9,
                            constants.HYPERV_VM_STATE_SUSPENDED: 6}

    _DEFAULT_EVENT_CHECK_TIMEFRAME = 60  # seconds
    _DEFAULT_EVENT_TIMEOUT_MS = 2000

    def __init__(self, host='.'):
        super(VMUtils, self).__init__(host)
        self._jobutils = jobutils.JobUtils(host)
        self._pathutils = pathutils.PathUtils()
        self._enabled_states_map = {v: k for k, v in
                                    six.iteritems(self._vm_power_states_map)}

    def list_instance_notes(self):
        instance_notes = []

        for vs in self._conn.Msvm_VirtualSystemSettingData(
                ['ElementName', 'Notes'],
                VirtualSystemType=self._VIRTUAL_SYSTEM_TYPE_REALIZED):
            vs_notes = vs.Notes
            vs_name = vs.ElementName
            if vs_notes is not None and vs_name:
                instance_notes.append(
                    (vs_name, [v for v in vs_notes if v]))

        return instance_notes

    def list_instances(self):
        """Return the names of all the instances known to Hyper-V."""

        return [v.ElementName for v in
                self._conn.Msvm_VirtualSystemSettingData(
                    ['ElementName'],
                    VirtualSystemType=self._VIRTUAL_SYSTEM_TYPE_REALIZED)]

    def get_vm_summary_info(self, vm_name):
        vmsettings = self._lookup_vm_check(vm_name)

        settings_paths = [vmsettings.path_()]
        # See http://msdn.microsoft.com/en-us/library/cc160706%28VS.85%29.aspx
        (ret_val, summary_info) = self._vs_man_svc.GetSummaryInformation(
            [constants.VM_SUMMARY_NUM_PROCS,
             constants.VM_SUMMARY_ENABLED_STATE,
             constants.VM_SUMMARY_MEMORY_USAGE,
             constants.VM_SUMMARY_UPTIME],
            settings_paths)
        if ret_val:
            raise exceptions.HyperVException(
                _('Cannot get VM summary data for: %s') % vm_name)

        si = summary_info[0]
        memory_usage = None
        if si.MemoryUsage is not None:
            memory_usage = int(si.MemoryUsage)
        up_time = None
        if si.UpTime is not None:
            up_time = int(si.UpTime)

        # Nova requires a valid state to be returned. Hyper-V has more
        # states than Nova, typically intermediate ones and since there is
        # no direct mapping for those, ENABLED is the only reasonable option
        # considering that in all the non mappable states the instance
        # is running.
        enabled_state = self._enabled_states_map.get(si.EnabledState,
                                                     constants.
                                                     HYPERV_VM_STATE_ENABLED)

        summary_info_dict = {'NumberOfProcessors': si.NumberOfProcessors,
                             'EnabledState': enabled_state,
                             'MemoryUsage': memory_usage,
                             'UpTime': up_time}
        return summary_info_dict

    def get_vm_state(self, vm_name):
        settings = self.get_vm_summary_info(vm_name)
        return settings['EnabledState']

    def _lookup_vm_check(self, vm_name, as_vssd=True, for_update=False,
                         virtual_system_type=_VIRTUAL_SYSTEM_TYPE_REALIZED):
        vm = self._lookup_vm(vm_name, as_vssd, for_update,
                             virtual_system_type)
        if not vm:
            raise exceptions.HyperVVMNotFoundException(vm_name=vm_name)
        return vm

    def _lookup_vm(self, vm_name, as_vssd=True, for_update=False,
                   virtual_system_type=_VIRTUAL_SYSTEM_TYPE_REALIZED):
        if as_vssd:
            conn = self._compat_conn if for_update else self._conn
            vms = conn.Msvm_VirtualSystemSettingData(
                ElementName=vm_name,
                VirtualSystemType=virtual_system_type)
        else:
            vms = self._conn.Msvm_ComputerSystem(ElementName=vm_name)
        n = len(vms)
        if n == 0:
            return None
        elif n > 1:
            raise exceptions.HyperVException(
                _('Duplicate VM name found: %s') % vm_name)
        else:
            return vms[0]

    def vm_exists(self, vm_name):
        return self._lookup_vm(vm_name) is not None

    def get_vm_id(self, vm_name):
        vm = self._lookup_vm_check(vm_name, as_vssd=False)
        return vm.Name

    def _set_vm_memory(self, vmsetting, memory_mb, memory_per_numa_node,
                       dynamic_memory_ratio):
        mem_settings = _wqlutils.get_element_associated_class(
            self._compat_conn, self._MEMORY_SETTING_DATA_CLASS,
            element_instance_id=vmsetting.InstanceID)[0]

        max_mem = int(memory_mb)
        mem_settings.Limit = max_mem

        if dynamic_memory_ratio > 1:
            mem_settings.DynamicMemoryEnabled = True
            # Must be a multiple of 2
            reserved_mem = min(
                int(max_mem / dynamic_memory_ratio) >> 1 << 1,
                max_mem)
        else:
            mem_settings.DynamicMemoryEnabled = False
            reserved_mem = max_mem

        mem_settings.Reservation = reserved_mem
        # Start with the minimum memory
        mem_settings.VirtualQuantity = reserved_mem

        if memory_per_numa_node:
            # One memory block is 1 MB.
            mem_settings.MaxMemoryBlocksPerNumaNode = memory_per_numa_node

        self._jobutils.modify_virt_resource(mem_settings)

    def _set_vm_vcpus(self, vmsetting, vcpus_num, vcpus_per_numa_node,
                      limit_cpu_features):
        procsetting = _wqlutils.get_element_associated_class(
            self._compat_conn, self._PROCESSOR_SETTING_DATA_CLASS,
            element_instance_id=vmsetting.InstanceID)[0]

        vcpus = int(vcpus_num)
        procsetting.VirtualQuantity = vcpus
        procsetting.Reservation = vcpus
        procsetting.Limit = 100000  # static assignment to 100%
        procsetting.LimitProcessorFeatures = limit_cpu_features

        if vcpus_per_numa_node:
            procsetting.MaxProcessorsPerNumaNode = vcpus_per_numa_node

        self._jobutils.modify_virt_resource(procsetting)

    def update_vm(self, vm_name, memory_mb, memory_per_numa_node, vcpus_num,
                  vcpus_per_numa_node, limit_cpu_features, dynamic_mem_ratio,
                  configuration_root_dir=None, snapshot_dir=None,
                  host_shutdown_action=None,
                  is_planned_vm=False):
        virtual_system_type = self._get_virtual_system_type(is_planned_vm)

        vmsetting = self._lookup_vm_check(
            vm_name, virtual_system_type=virtual_system_type)

        if host_shutdown_action:
            vmsetting.AutomaticShutdownAction = host_shutdown_action
        if configuration_root_dir:
            vmsetting.ConfigurationDataRoot = configuration_root_dir
        if snapshot_dir:
            vmsetting.SnapshotDataRoot = snapshot_dir
        self._set_vm_memory(vmsetting, memory_mb, memory_per_numa_node,
                            dynamic_mem_ratio)
        self._set_vm_vcpus(vmsetting, vcpus_num, vcpus_per_numa_node,
                           limit_cpu_features)

        update_needed = (configuration_root_dir or snapshot_dir or
                         host_shutdown_action)
        if update_needed:
            self._modify_virtual_system(vmsetting)

    def check_admin_permissions(self):
        if not self._compat_conn.Msvm_VirtualSystemManagementService():
            raise exceptions.HyperVAuthorizationException()

    def create_vm(self, *args, **kwargs):
        # TODO(claudiub): method signature changed. Fix this when the usage
        # for this method was updated.
        # update_vm should be called in order to set VM's memory and vCPUs.
        try:
            self._create_vm(*args, **kwargs)
        except TypeError:
            # the method call was updated to use the _vnuma_create_vm interface
            self._vnuma_create_vm(*args, **kwargs)

    def _vnuma_create_vm(self, vm_name, vnuma_enabled, vm_gen, instance_path,
                         notes=None):
        LOG.debug('Creating VM %s', vm_name)
        self._create_vm_obj(vm_name, vnuma_enabled, vm_gen, notes,
                            instance_path)

    def _create_vm(self, vm_name, memory_mb, vcpus_num, limit_cpu_features,
                   dynamic_memory_ratio, vm_gen, instance_path, notes=None):
        """Creates a VM."""

        LOG.debug('Creating VM %s', vm_name)

        # vNUMA and dynamic memory are mutually exclusive
        vnuma_enabled = False if dynamic_memory_ratio > 1 else True

        self._create_vm_obj(vm_name, vnuma_enabled, vm_gen, notes,
                            instance_path)

        vmsetting = self._lookup_vm_check(vm_name)

        LOG.debug('Setting memory for vm %s', vm_name)
        self._set_vm_memory(vmsetting, memory_mb, None, dynamic_memory_ratio)

        LOG.debug('Set vCPUs for vm %s', vm_name)
        self._set_vm_vcpus(vmsetting, vcpus_num, None, limit_cpu_features)

    def _create_vm_obj(self, vm_name, vnuma_enabled, vm_gen, notes,
                       instance_path):
        vs_data = self._compat_conn.Msvm_VirtualSystemSettingData.new()
        vs_data.ElementName = vm_name
        vs_data.Notes = notes
        # Don't start automatically on host boot
        vs_data.AutomaticStartupAction = self._AUTOMATIC_STARTUP_ACTION_NONE

        vs_data.VirtualNumaEnabled = vnuma_enabled

        if vm_gen == constants.VM_GEN_2:
            vs_data.VirtualSystemSubType = self._VIRTUAL_SYSTEM_SUBTYPE_GEN2
            vs_data.SecureBootEnabled = False

        # Created VMs must have their *DataRoot paths in the same location as
        # the instances' path.
        vs_data.ConfigurationDataRoot = instance_path
        vs_data.LogDataRoot = instance_path
        vs_data.SnapshotDataRoot = instance_path
        vs_data.SuspendDataRoot = instance_path
        vs_data.SwapFileDataRoot = instance_path

        (job_path,
         vm_path,
         ret_val) = self._vs_man_svc.DefineSystem(
            ResourceSettings=[], ReferenceConfiguration=None,
            SystemSettings=vs_data.GetText_(1))
        self._jobutils.check_ret_val(ret_val, job_path)

    @_utils.retry_decorator(exceptions=exceptions.HyperVException)
    def _modify_virtual_system(self, vmsetting):
        (job_path, ret_val) = self._vs_man_svc.ModifySystemSettings(
            SystemSettings=vmsetting.GetText_(1))
        self._jobutils.check_ret_val(ret_val, job_path)

    def get_vm_scsi_controller(self, vm_name):
        vmsettings = self._lookup_vm_check(vm_name)
        return self._get_vm_scsi_controller(vmsettings)

    def _get_vm_scsi_controller(self, vmsettings):
        rasds = _wqlutils.get_element_associated_class(
            self._conn, self._RESOURCE_ALLOC_SETTING_DATA_CLASS,
            element_instance_id=vmsettings.InstanceID)
        res = [r for r in rasds
               if r.ResourceSubType == self._SCSI_CTRL_RES_SUB_TYPE][0]
        return res.path_()

    def _get_vm_ide_controller(self, vmsettings, ctrller_addr):
        rasds = _wqlutils.get_element_associated_class(
            self._conn, self._RESOURCE_ALLOC_SETTING_DATA_CLASS,
            element_instance_id=vmsettings.InstanceID)
        ide_ctrls = [r for r in rasds
                     if r.ResourceSubType == self._IDE_CTRL_RES_SUB_TYPE and
                     r.Address == str(ctrller_addr)]

        return ide_ctrls[0].path_() if ide_ctrls else None

    def get_vm_ide_controller(self, vm_name, ctrller_addr):
        vmsettings = self._lookup_vm_check(vm_name)
        return self._get_vm_ide_controller(vmsettings, ctrller_addr)

    def get_attached_disks(self, scsi_controller_path):
        volumes = self._conn.query(
            self._get_attached_disks_query_string(scsi_controller_path))
        return volumes

    def _get_attached_disks_query_string(self, scsi_controller_path):
        # DVD Drives can be attached to SCSI as well, if the VM Generation is 2
        return ("SELECT * FROM Msvm_ResourceAllocationSettingData WHERE ("
                "ResourceSubType='%(res_sub_type)s' OR "
                "ResourceSubType='%(res_sub_type_virt)s' OR "
                "ResourceSubType='%(res_sub_type_dvd)s') AND "
                "Parent = '%(parent)s'" % {
                    'res_sub_type': self._PHYS_DISK_RES_SUB_TYPE,
                    'res_sub_type_virt': self._DISK_DRIVE_RES_SUB_TYPE,
                    'res_sub_type_dvd': self._DVD_DRIVE_RES_SUB_TYPE,
                    'parent': scsi_controller_path.replace("'", "''")})

    def _get_new_setting_data(self, class_name):
        obj = self._compat_conn.query("SELECT * FROM %s WHERE InstanceID "
                                      "LIKE '%%\\Default'" % class_name)[0]
        return obj

    def _get_new_resource_setting_data(self, resource_sub_type,
                                       class_name=None):
        if class_name is None:
            class_name = self._RESOURCE_ALLOC_SETTING_DATA_CLASS
        obj = self._compat_conn.query("SELECT * FROM %(class_name)s "
                                      "WHERE ResourceSubType = "
                                      "'%(res_sub_type)s' AND "
                                      "InstanceID LIKE '%%\\Default'" %
                                      {"class_name": class_name,
                                       "res_sub_type": resource_sub_type})[0]
        return obj

    def attach_scsi_drive(self, vm_name, path, drive_type=constants.DISK):
        vmsettings = self._lookup_vm_check(vm_name)
        ctrller_path = self._get_vm_scsi_controller(vmsettings)
        drive_addr = self.get_free_controller_slot(ctrller_path)
        self.attach_drive(vm_name, path, ctrller_path, drive_addr, drive_type)

    def attach_ide_drive(self, vm_name, path, ctrller_addr, drive_addr,
                         drive_type=constants.DISK):
        vmsettings = self._lookup_vm_check(vm_name)
        ctrller_path = self._get_vm_ide_controller(vmsettings, ctrller_addr)
        self.attach_drive(vm_name, path, ctrller_path, drive_addr, drive_type)

    def attach_drive(self, vm_name, path, ctrller_path, drive_addr,
                     drive_type=constants.DISK):
        """Create a drive and attach it to the vm."""

        vm = self._lookup_vm_check(vm_name, as_vssd=False)

        if drive_type == constants.DISK:
            res_sub_type = self._DISK_DRIVE_RES_SUB_TYPE
        elif drive_type == constants.DVD:
            res_sub_type = self._DVD_DRIVE_RES_SUB_TYPE

        drive = self._get_new_resource_setting_data(res_sub_type)

        # Set the ctrller as parent.
        drive.Parent = ctrller_path
        drive.Address = drive_addr
        drive.AddressOnParent = drive_addr
        # Add the cloned disk drive object to the vm.
        new_resources = self._jobutils.add_virt_resource(drive, vm)
        drive_path = new_resources[0]

        if drive_type == constants.DISK:
            res_sub_type = self._HARD_DISK_RES_SUB_TYPE
        elif drive_type == constants.DVD:
            res_sub_type = self._DVD_DISK_RES_SUB_TYPE

        res = self._get_new_resource_setting_data(
            res_sub_type, self._STORAGE_ALLOC_SETTING_DATA_CLASS)

        res.Parent = drive_path
        res.HostResource = [path]

        # Add the new vhd object as a virtual hard disk to the vm.
        self._jobutils.add_virt_resource(res, vm)

    def create_scsi_controller(self, vm_name):
        """Create an iscsi controller ready to mount volumes."""

        vmsettings = self._lookup_vm_check(vm_name)
        scsicontrl = self._get_new_resource_setting_data(
            self._SCSI_CTRL_RES_SUB_TYPE)

        scsicontrl.VirtualSystemIdentifiers = ['{' + str(uuid.uuid4()) + '}']
        self._jobutils.add_virt_resource(scsicontrl, vmsettings)

    def attach_volume_to_controller(self, vm_name, controller_path, address,
                                    mounted_disk_path, serial=None):
        """Attach a volume to a controller."""

        vmsettings = self._lookup_vm_check(vm_name)

        diskdrive = self._get_new_resource_setting_data(
            self._PHYS_DISK_RES_SUB_TYPE)

        diskdrive.AddressOnParent = address
        diskdrive.Parent = controller_path
        diskdrive.HostResource = [mounted_disk_path]

        diskdrive_path = self._jobutils.add_virt_resource(diskdrive,
                                                          vmsettings)[0]

        if serial:
            # Apparently this can't be set when the resource is added.
            diskdrive = self._get_wmi_obj(diskdrive_path, True)
            diskdrive.ElementName = serial
            self._jobutils.modify_virt_resource(diskdrive)

    def get_vm_physical_disk_mapping(self, vm_name, is_planned_vm=False):
        mapping = {}
        physical_disks = (
            self.get_vm_disks(vm_name, is_planned_vm=is_planned_vm)[1])
        for diskdrive in physical_disks:
            mapping[diskdrive.ElementName] = dict(
                resource_path=diskdrive.path_(),
                mounted_disk_path=diskdrive.HostResource[0])
        return mapping

    def _get_disk_resource_address(self, disk_resource):
        return disk_resource.AddressOnParent

    def set_disk_host_res(self, disk_res_path, mounted_disk_path):
        diskdrive = self._get_wmi_obj(disk_res_path, True)
        diskdrive.HostResource = [mounted_disk_path]
        self._jobutils.modify_virt_resource(diskdrive)

    def set_disk_host_resource(self, vm_name, controller_path, address,
                               mounted_disk_path):
        # TODO(lpetrut): remove this method after the patch fixing
        # swapped disks after host reboot merges in Nova.
        disk_found = False
        vmsettings = self._lookup_vm_check(vm_name)
        (disk_resources, volume_resources) = self._get_vm_disks(vmsettings)
        for disk_resource in disk_resources + volume_resources:
            if (disk_resource.Parent == controller_path and
                    self._get_disk_resource_address(disk_resource) ==
                    str(address)):
                if (disk_resource.HostResource and
                        disk_resource.HostResource[0] != mounted_disk_path):
                    LOG.debug('Updating disk host resource "%(old)s" to '
                              '"%(new)s"' %
                              {'old': disk_resource.HostResource[0],
                               'new': mounted_disk_path})
                    disk_resource.HostResource = [mounted_disk_path]
                    self._jobutils.modify_virt_resource(disk_resource)
                disk_found = True
                break
        if not disk_found:
            LOG.warning(_LW('Disk not found on controller '
                            '"%(controller_path)s" with '
                            'address "%(address)s"'),
                        {'controller_path': controller_path,
                         'address': address})

    def _get_nic_data_by_name(self, name):
        return self._conn.Msvm_SyntheticEthernetPortSettingData(
            ElementName=name)[0]

    def create_nic(self, vm_name, nic_name, mac_address):
        """Create a (synthetic) nic and attach it to the vm."""
        # Create a new nic
        new_nic_data = self._get_new_setting_data(
            self._SYNTHETIC_ETHERNET_PORT_SETTING_DATA_CLASS)

        # Configure the nic
        new_nic_data.ElementName = nic_name
        new_nic_data.Address = mac_address.replace(':', '')
        new_nic_data.StaticMacAddress = 'True'
        new_nic_data.VirtualSystemIdentifiers = ['{' + str(uuid.uuid4()) + '}']

        # Add the new nic to the vm
        vmsettings = self._lookup_vm_check(vm_name)

        self._jobutils.add_virt_resource(new_nic_data, vmsettings)

    def destroy_nic(self, vm_name, nic_name):
        """Destroys the NIC with the given nic_name from the given VM.

        :param vm_name: The name of the VM which has the NIC to be destroyed.
        :param nic_name: The NIC's ElementName.
        """
        # TODO(claudiub): remove vm_name argument, no longer used.
        nic_data = self._get_nic_data_by_name(nic_name)
        self._jobutils.remove_virt_resource(nic_data)

    def soft_shutdown_vm(self, vm_name):
        vm = self._lookup_vm_check(vm_name, as_vssd=False)
        shutdown_component = self._conn.Msvm_ShutdownComponent(
            SystemName=vm.Name)

        if not shutdown_component:
            # If no shutdown_component is found, it means the VM is already
            # in a shutdown state.
            return

        reason = 'Soft shutdown requested by OpenStack Nova.'
        (ret_val, ) = shutdown_component[0].InitiateShutdown(Force=False,
                                                             Reason=reason)
        self._jobutils.check_ret_val(ret_val, None)

    def set_vm_state(self, vm_name, req_state):
        """Set the desired state of the VM."""

        vm = self._lookup_vm_check(vm_name, as_vssd=False)
        (job_path,
         ret_val) = vm.RequestStateChange(self._vm_power_states_map[req_state])
        # Invalid state for current operation (32775) typically means that
        # the VM is already in the state requested
        self._jobutils.check_ret_val(ret_val, job_path, [0, 32775])
        LOG.debug("Successfully changed vm state of %(vm_name)s "
                  "to %(req_state)s",
                  {'vm_name': vm_name, 'req_state': req_state})

    def _get_disk_resource_disk_path(self, disk_resource):
        return disk_resource.HostResource

    def get_vm_config_root_dir(self, vm_name):
        vmsettings = self._lookup_vm_check(vm_name)
        return vmsettings.ConfigurationDataRoot

    def get_vm_storage_paths(self, vm_name, is_planned_vm=False):
        virtual_system_type = self._get_virtual_system_type(is_planned_vm)
        vmsettings = self._lookup_vm_check(
            vm_name,
            virtual_system_type=virtual_system_type)
        (disk_resources, volume_resources) = self._get_vm_disks(vmsettings)

        volume_drives = []
        for volume_resource in volume_resources:
            drive_path = volume_resource.HostResource[0]
            volume_drives.append(drive_path)

        disk_files = []
        for disk_resource in disk_resources:
            disk_files.extend(
                [c for c in self._get_disk_resource_disk_path(disk_resource)])

        return (disk_files, volume_drives)

    def get_vm_disks(self, vm_name, is_planned_vm=False):
        virtual_system_type = self._get_virtual_system_type(is_planned_vm)
        vmsettings = self._lookup_vm_check(
            vm_name, virtual_system_type=virtual_system_type)
        return self._get_vm_disks(vmsettings)

    def _get_vm_disks(self, vmsettings):
        rasds = _wqlutils.get_element_associated_class(
            self._compat_conn, self._STORAGE_ALLOC_SETTING_DATA_CLASS,
            element_instance_id=vmsettings.InstanceID)
        disk_resources = [r for r in rasds if
                          r.ResourceSubType in
                          [self._HARD_DISK_RES_SUB_TYPE,
                           self._DVD_DISK_RES_SUB_TYPE]]

        if (self._RESOURCE_ALLOC_SETTING_DATA_CLASS !=
                self._STORAGE_ALLOC_SETTING_DATA_CLASS):
            rasds = _wqlutils.get_element_associated_class(
                self._compat_conn, self._RESOURCE_ALLOC_SETTING_DATA_CLASS,
                element_instance_id=vmsettings.InstanceID)

        volume_resources = [r for r in rasds if
                            r.ResourceSubType == self._PHYS_DISK_RES_SUB_TYPE]

        return (disk_resources, volume_resources)

    def destroy_vm(self, vm_name):
        vm = self._lookup_vm_check(vm_name, as_vssd=False)

        # Remove the VM. It does not destroy any associated virtual disk.
        (job_path, ret_val) = self._vs_man_svc.DestroySystem(vm.path_())
        self._jobutils.check_ret_val(ret_val, job_path)

    def take_vm_snapshot(self, vm_name):
        vm = self._lookup_vm_check(vm_name, as_vssd=False)
        vs_snap_svc = self._compat_conn.Msvm_VirtualSystemSnapshotService()[0]

        (job_path, snp_setting_data, ret_val) = vs_snap_svc.CreateSnapshot(
            AffectedSystem=vm.path_(),
            SnapshotType=self._SNAPSHOT_FULL)
        self._jobutils.check_ret_val(ret_val, job_path)

        vm_path = vm.path_().lower()
        current_snapshots = self._conn.Msvm_MostCurrentSnapshotInBranch()
        snp_setting_data = [s for s in current_snapshots if
                            s.Antecedent.path_().lower() == vm_path][0]

        return snp_setting_data.Dependent.path_()

    def remove_vm_snapshot(self, snapshot_path):
        vs_snap_svc = self._compat_conn.Msvm_VirtualSystemSnapshotService()[0]
        (job_path, ret_val) = vs_snap_svc.DestroySnapshot(snapshot_path)
        self._jobutils.check_ret_val(ret_val, job_path)

    def get_vm_dvd_disk_paths(self, vm_name):
        vmsettings = self._lookup_vm_check(vm_name)

        sasds = _wqlutils.get_element_associated_class(
            self._conn, self._STORAGE_ALLOC_SETTING_DATA_CLASS,
            element_instance_id=vmsettings.InstanceID)

        dvd_paths = [sasd.HostResource[0] for sasd in sasds
                     if sasd.ResourceSubType == self._DVD_DISK_RES_SUB_TYPE]

        return dvd_paths

    def is_disk_attached(self, disk_path, is_physical=True):
        disk_resource = self._get_mounted_disk_resource_from_path(disk_path,
                                                                  is_physical)
        return disk_resource is not None

    def detach_vm_disk(self, vm_name, disk_path, is_physical=True):
        # TODO(claudiub): remove vm_name argument, no longer used.
        disk_resource = self._get_mounted_disk_resource_from_path(disk_path,
                                                                  is_physical)

        if disk_resource:
            parent = self._conn.query("SELECT * FROM "
                                      "Msvm_ResourceAllocationSettingData "
                                      "WHERE __PATH = '%s'" %
                                      disk_resource.Parent)[0]

            self._jobutils.remove_virt_resource(disk_resource)
            if not is_physical:
                self._jobutils.remove_virt_resource(parent)

    def _get_mounted_disk_resource_from_path(self, disk_path, is_physical):
        if is_physical:
            class_name = self._RESOURCE_ALLOC_SETTING_DATA_CLASS
        else:
            class_name = self._STORAGE_ALLOC_SETTING_DATA_CLASS

        query = ("SELECT * FROM %(class_name)s WHERE ("
                 "ResourceSubType='%(res_sub_type)s' OR "
                 "ResourceSubType='%(res_sub_type_virt)s' OR "
                 "ResourceSubType='%(res_sub_type_dvd)s')" % {
                     'class_name': class_name,
                     'res_sub_type': self._PHYS_DISK_RES_SUB_TYPE,
                     'res_sub_type_virt': self._HARD_DISK_RES_SUB_TYPE,
                     'res_sub_type_dvd': self._DVD_DISK_RES_SUB_TYPE})

        disk_resources = self._compat_conn.query(query)

        for disk_resource in disk_resources:
            if disk_resource.HostResource:
                if disk_resource.HostResource[0].lower() == disk_path.lower():
                    return disk_resource

    def get_mounted_disk_by_drive_number(self, device_number):
        mounted_disks = self._conn.query("SELECT * FROM Msvm_DiskDrive "
                                         "WHERE DriveNumber=" +
                                         str(device_number))
        if len(mounted_disks):
            return mounted_disks[0].path_()

    def get_controller_volume_paths(self, controller_path):
        disks = self._conn.query("SELECT * FROM %(class_name)s "
                                 "WHERE ResourceSubType = '%(res_sub_type)s' "
                                 "AND Parent='%(parent)s'" %
                                 {"class_name":
                                  self._RESOURCE_ALLOC_SETTING_DATA_CLASS,
                                  "res_sub_type":
                                  self._PHYS_DISK_RES_SUB_TYPE,
                                  "parent":
                                  controller_path})
        disk_data = {}
        for disk in disks:
            if disk.HostResource:
                disk_data[disk.path().RelPath] = disk.HostResource[0]
        return disk_data

    def get_free_controller_slot(self, scsi_controller_path):
        attached_disks = self.get_attached_disks(scsi_controller_path)
        used_slots = [int(disk.AddressOnParent) for disk in attached_disks]

        for slot in range(constants.SCSI_CONTROLLER_SLOTS_NUMBER):
            if slot not in used_slots:
                return slot
        raise exceptions.HyperVException(
            _("Exceeded the maximum number of slots"))

    def get_vm_serial_port_connection(self, vm_name, update_connection=None):
        # TODO(lpetrut): Remove this method after the patch implementing
        # serial console access support merges in Nova.
        vmsettings = self._lookup_vm_check(vm_name)

        rasds = _wqlutils.get_element_associated_class(
            self._compat_conn, self._SERIAL_PORT_SETTING_DATA_CLASS,
            element_instance_id=vmsettings.InstanceID)
        serial_port = (
            [r for r in rasds if
             r.ResourceSubType == self._SERIAL_PORT_RES_SUB_TYPE][0])

        if update_connection:
            serial_port.Connection = [update_connection]
            self._jobutils.modify_virt_resource(serial_port)

        if len(serial_port.Connection) > 0:
            return serial_port.Connection[0]

    def _get_vm_serial_ports(self, vmsettings):
        rasds = _wqlutils.get_element_associated_class(
            self._compat_conn, self._SERIAL_PORT_SETTING_DATA_CLASS,
            element_instance_id=vmsettings.InstanceID)
        serial_ports = (
            [r for r in rasds if
             r.ResourceSubType == self._SERIAL_PORT_RES_SUB_TYPE]
        )
        return serial_ports

    def set_vm_serial_port_connection(self, vm_name, port_number, pipe_path):
        vmsettings = self._lookup_vm_check(vm_name)

        serial_port = self._get_vm_serial_ports(vmsettings)[port_number - 1]
        serial_port.Connection = [pipe_path]

        self._jobutils.modify_virt_resource(serial_port)

    def get_vm_serial_port_connections(self, vm_name):
        vmsettings = self._lookup_vm_check(vm_name)
        serial_ports = self._get_vm_serial_ports(vmsettings)
        conns = [serial_port.Connection[0]
                 for serial_port in serial_ports
                 if serial_port.Connection and serial_port.Connection[0]]
        return conns

    def get_active_instances(self):
        """Return the names of all the active instances known to Hyper-V."""

        vm_names = self.list_instances()
        vms = [self._lookup_vm(vm_name, as_vssd=False) for vm_name in vm_names]
        active_vm_names = [v.ElementName for v in vms
                           if v.EnabledState ==
                           constants.HYPERV_VM_STATE_ENABLED]

        return active_vm_names

    def get_vm_power_state_change_listener(
            self, timeframe=_DEFAULT_EVENT_CHECK_TIMEFRAME,
            event_timeout=_DEFAULT_EVENT_TIMEOUT_MS,
            filtered_states=None, get_handler=False):
        field = self._VM_ENABLED_STATE_PROP
        query = self._get_event_wql_query(cls=self._COMPUTER_SYSTEM_CLASS,
                                          field=field,
                                          timeframe=timeframe,
                                          filtered_states=filtered_states)
        listener = self._conn.Msvm_ComputerSystem.watch_for(raw_wql=query,
                                                            fields=[field])

        def _handle_events(callback):
            if patcher.is_monkey_patched('thread'):
                # Retrieve one by one all the events that occurred in
                # the checked interval.
                #
                # We use eventlet.tpool for retrieving the events in
                # order to avoid issues caused by greenthread/thread
                # communication. Note that PyMI must use the unpatched
                # threading module.
                listen = functools.partial(tpool.execute, listener,
                                           event_timeout)
            else:
                listen = functools.partial(listener, event_timeout)

            while True:
                try:
                    event = listen()

                    vm_name = event.ElementName
                    vm_state = event.EnabledState
                    vm_power_state = self.get_vm_power_state(vm_state)

                    try:
                        callback(vm_name, vm_power_state)
                    except Exception:
                        err_msg = _LE("Executing VM power state change event "
                                      "callback failed. "
                                      "VM name: %(vm_name)s, "
                                      "VM power state: %(vm_power_state)s.")
                        LOG.exception(err_msg,
                                      dict(vm_name=vm_name,
                                           vm_power_state=vm_power_state))
                except exceptions.x_wmi_timed_out:
                    pass
                except Exception:
                    LOG.exception(
                        _LE("The VM power state change event listener "
                            "encountered an unexpected exception."))
                    time.sleep(event_timeout / 1000)

        return _handle_events if get_handler else listener

    def _get_event_wql_query(self, cls, field,
                             timeframe, filtered_states=None):
        """Return a WQL query used for polling WMI events.

            :param cls: the WMI class polled for events
            :param field: the field checked
            :param timeframe: check for events that occurred in
                              the specified timeframe
            :param filtered_states: only catch events triggered when a WMI
                                    object transitioned into one of those
                                    states.
        """

        query = ("SELECT %(field)s, TargetInstance "
                 "FROM __InstanceModificationEvent "
                 "WITHIN %(timeframe)s "
                 "WHERE TargetInstance ISA '%(class)s' "
                 "AND TargetInstance.%(field)s != "
                 "PreviousInstance.%(field)s" %
                 {'class': cls,
                  'field': field,
                  'timeframe': timeframe})
        if filtered_states:
            checks = ["TargetInstance.%s = '%s'" % (field, state)
                      for state in filtered_states]
            query += " AND (%s)" % " OR ".join(checks)
        return query

    def _get_instance_notes(self, vm_name):
        vmsettings = self._lookup_vm_check(vm_name)
        vm_notes = vmsettings.Notes or []
        return [note for note in vm_notes if note]

    def get_instance_uuid(self, vm_name):
        instance_notes = self._get_instance_notes(vm_name)
        if instance_notes and uuidutils.is_uuid_like(instance_notes[0]):
            return instance_notes[0]

    def get_vm_power_state(self, vm_enabled_state):
        return self._enabled_states_map.get(vm_enabled_state,
                                            constants.HYPERV_VM_STATE_OTHER)

    def get_vm_generation(self, vm_name):
        vssd = self._lookup_vm_check(vm_name)
        try:
            # expected format: 'Microsoft:Hyper-V:SubType:2'
            return int(vssd.VirtualSystemSubType.split(':')[-1])
        except Exception:
            # NOTE(claudiub): The Msvm_VirtualSystemSettingData object does not
            # contain the VirtualSystemSubType field on Windows Hyper-V /
            # Server 2012.
            pass
        return constants.VM_GEN_1

    def stop_vm_jobs(self, vm_name):
        vm = self._lookup_vm_check(vm_name, as_vssd=False)
        self._jobutils.stop_jobs(vm)

    def enable_secure_boot(self, vm_name, msft_ca_required):
        """Enables Secure Boot for the instance with the given name.

        :param vm_name: The name of the VM for which Secure Boot will be
                        enabled.
        :param msft_ca_required: boolean specifying whether the VM will
                                 require Microsoft UEFI Certificate
                                 Authority for Secure Boot. Only Linux
                                 guests require this CA.
        """

        vs_data = self._lookup_vm_check(vm_name)
        self._set_secure_boot(vs_data, msft_ca_required)
        self._modify_virtual_system(vs_data)

    def _set_secure_boot(self, vs_data, msft_ca_required):
        vs_data.SecureBootEnabled = True
        if msft_ca_required:
            raise exceptions.HyperVException(
                _('UEFI SecureBoot is supported only on Windows instances for '
                  'this Hyper-V version.'))

    def set_disk_qos_specs(self, disk_path, max_iops=None, min_iops=None):
        if min_iops is None and max_iops is None:
            LOG.debug("Skipping setting disk QoS specs as no "
                      "value was provided.")
            return

        disk_resource = self._get_mounted_disk_resource_from_path(
            disk_path, is_physical=False)

        if max_iops is not None:
            disk_resource.IOPSLimit = max_iops
        if min_iops is not None:
            disk_resource.IOPSReservation = min_iops

        self._jobutils.modify_virt_resource(disk_resource)

    def _is_drive_physical(self, drive_path):
        # TODO(atuvenie): Find better way to check if path represents
        # physical or virtual drive.
        return not self._pathutils.exists(drive_path)

    def _drive_to_boot_source(self, drive_path):
        is_physical = self._is_drive_physical(drive_path)
        drive = self._get_mounted_disk_resource_from_path(
            drive_path, is_physical=is_physical)

        rasd_path = drive.path_() if is_physical else drive.Parent
        bssd = self._conn.Msvm_LogicalIdentity(
            SystemElement=rasd_path)[0].SameElement

        return bssd.path_()

    def set_boot_order(self, vm_name, device_boot_order):
        if self.get_vm_generation(vm_name) == constants.VM_GEN_1:
            self._set_boot_order_gen1(vm_name, device_boot_order)
        else:
            self._set_boot_order_gen2(vm_name, device_boot_order)

    def _set_boot_order_gen1(self, vm_name, device_boot_order):
        vssd = self._lookup_vm_check(vm_name, for_update=True)
        vssd.BootOrder = tuple(device_boot_order)

        self._modify_virtual_system(vssd)

    def _set_boot_order_gen2(self, vm_name, device_boot_order):
        new_boot_order = [(self._drive_to_boot_source(device))
                          for device in device_boot_order if device]

        vssd = self._lookup_vm_check(vm_name)
        old_boot_order = vssd.BootSourceOrder

        # NOTE(abalutoiu): new_boot_order will contain ROOT uppercase
        # in the device paths while old_boot_order will contain root
        # lowercase, which will cause the tupple addition result to contain
        # each device path twice because of the root lowercase and uppercase.
        # Forcing all the device paths to uppercase fixes the issue.
        new_boot_order = [x.upper() for x in new_boot_order]
        old_boot_order = [x.upper() for x in old_boot_order]
        network_boot_devs = set(old_boot_order) ^ set(new_boot_order)
        vssd.BootSourceOrder = tuple(new_boot_order) + tuple(network_boot_devs)
        self._modify_virtual_system(vssd)

    def vm_gen_supports_remotefx(self, vm_gen):
        """RemoteFX is supported only for generation 1 virtual machines

        on Windows 8 / Windows Server 2012 and 2012R2.

        :returns: True if the given vm_gen is 1, False otherwise
        """

        return vm_gen == constants.VM_GEN_1

    def _validate_remotefx_params(self, monitor_count, max_resolution,
                                  vram_bytes=None):
        max_res_value = self._remote_fx_res_map.get(max_resolution)
        if max_res_value is None:
            raise exceptions.HyperVRemoteFXException(
                _("Unsupported RemoteFX resolution: %s") % max_resolution)

        if monitor_count > self._remotefx_max_monitors_map[max_resolution]:
            raise exceptions.HyperVRemoteFXException(
                _("Unsuported RemoteFX monitor count: %(count)s for "
                  "this resolution %(res)s. Hyper-V supports a maximum "
                  "of %(max_monitors)s monitors for this resolution.")
                % {'count': monitor_count,
                   'res': max_resolution,
                   'max_monitors':
                   self._remotefx_max_monitors_map[max_resolution]})

    def _add_3d_display_controller(self, vm, monitor_count,
                                   max_resolution, vram_bytes=None):
        synth_3d_disp_ctrl_res = self._get_new_resource_setting_data(
            self._SYNTH_3D_DISP_CTRL_RES_SUB_TYPE,
            self._SYNTH_3D_DISP_ALLOCATION_SETTING_DATA_CLASS)

        synth_3d_disp_ctrl_res.MaximumMonitors = monitor_count
        synth_3d_disp_ctrl_res.MaximumScreenResolution = max_resolution

        self._jobutils.add_virt_resource(synth_3d_disp_ctrl_res, vm)

    def enable_remotefx_video_adapter(self, vm_name, monitor_count,
                                      max_resolution, vram_bytes=None):
        vm = self._lookup_vm_check(vm_name, as_vssd=False)

        self._validate_remotefx_params(monitor_count, max_resolution,
                                       vram_bytes=vram_bytes)

        rasds = _wqlutils.get_element_associated_class(
            self._compat_conn, self._CIM_RES_ALLOC_SETTING_DATA_CLASS,
            element_uuid=vm.Name)
        if [r for r in rasds if r.ResourceSubType ==
                self._SYNTH_3D_DISP_CTRL_RES_SUB_TYPE]:
            raise exceptions.HyperVRemoteFXException(
                _("RemoteFX is already configured for this VM"))

        synth_disp_ctrl_res_list = [r for r in rasds if r.ResourceSubType ==
                                    self._SYNTH_DISP_CTRL_RES_SUB_TYPE]
        if synth_disp_ctrl_res_list:
            self._jobutils.remove_virt_resource(synth_disp_ctrl_res_list[0])

        max_res_value = self._remote_fx_res_map.get(max_resolution)
        self._add_3d_display_controller(vm, monitor_count, max_res_value,
                                        vram_bytes)
        if self._vm_has_s3_controller(vm.ElementName):
            s3_disp_ctrl_res = [r for r in rasds if r.ResourceSubType ==
                                self._S3_DISP_CTRL_RES_SUB_TYPE][0]
            s3_disp_ctrl_res.Address = self._DISP_CTRL_ADDRESS_DX_11
            self._jobutils.modify_virt_resource(s3_disp_ctrl_res)

    def _vm_has_s3_controller(self, vm_name):
        return True

    def is_secure_vm(self, instance_name):
        return False

    def update_vm_disk_path(self, disk_path, new_disk_path, is_physical=True):
        disk_resource = self._get_mounted_disk_resource_from_path(
            disk_path=disk_path, is_physical=is_physical)
        disk_resource.HostResource = [new_disk_path]
        self._jobutils.modify_virt_resource(disk_resource)

    def _get_virtual_system_type(self, is_planned_vm):
        return (
            self._VIRTUAL_SYSTEM_TYPE_PLANNED if is_planned_vm
            else self._VIRTUAL_SYSTEM_TYPE_REALIZED)
