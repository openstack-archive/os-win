#
# Copyright 2012 Pedro Navarro Perez
# Copyright 2013 Cloudbase Solutions Srl
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
Helper methods for operations related to the management of volumes,
and storage repositories
"""

import abc
import re
import sys

from oslo_log import log as logging

from os_win._i18n import _LI
from os_win.utils import baseutils

if sys.platform == 'win32':
    from six.moves import winreg

LOG = logging.getLogger(__name__)


class BaseISCSIInitiatorUtils(baseutils.BaseUtils):
    _FILE_DEVICE_DISK = 7

    def __init__(self, host='.'):
        self._conn_wmi = self._get_wmi_conn('//%s/root/wmi' % host)
        self._conn_cimv2 = self._get_wmi_conn('//%s/root/cimv2' % host)
        self._drive_number_regex = re.compile(r'DeviceID=\"[^,]*\\(\d+)\"')

    @abc.abstractmethod
    def login_storage_target(self, target_lun, target_iqn, target_portal):
        pass

    @abc.abstractmethod
    def logout_storage_target(self, target_iqn):
        pass

    @abc.abstractmethod
    def execute_log_out(self, session_id):
        pass

    def get_iscsi_initiator(self):
        """Get iscsi initiator name for this machine."""

        computer_system = self._conn_cimv2.Win32_ComputerSystem()[0]
        hostname = computer_system.name
        keypath = ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                   "iSCSI\\Discovery")
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                keypath,
                0,
                winreg.KEY_WOW64_64KEY + winreg.KEY_ALL_ACCESS)
            temp = winreg.QueryValueEx(key, 'DefaultInitiatorName')
            initiator_name = str(temp[0])
            winreg.CloseKey(key)
        except Exception:
            LOG.info(_LI("The ISCSI initiator name can't be found. "
                         "Choosing the default one"))
            initiator_name = "iqn.1991-05.com.microsoft:" + hostname.lower()
            if computer_system.PartofDomain:
                initiator_name += '.' + computer_system.Domain.lower()
        return initiator_name

    def _get_drive_number_from_disk_path(self, disk_path):
        drive_number = self._drive_number_regex.findall(disk_path)
        if drive_number:
            return int(drive_number[0])

    def get_session_id_from_mounted_disk(self, physical_drive_path):
        drive_number = self._get_drive_number_from_disk_path(
            physical_drive_path)
        if not drive_number:
            return None

        initiator_sessions = self._conn_wmi.MSiSCSIInitiator_SessionClass()
        for initiator_session in initiator_sessions:
            devices = initiator_session.Devices
            for device in devices:
                device_number = device.DeviceNumber
                if device_number == drive_number:
                    return initiator_session.SessionId

    def _get_devices_for_target(self, target_iqn):
        initiator_sessions = self._conn_wmi.MSiSCSIInitiator_SessionClass(
            TargetName=target_iqn)
        if not initiator_sessions:
            return []

        return initiator_sessions[0].Devices

    def get_device_number_for_target(self, target_iqn, target_lun):
        devices = self._get_devices_for_target(target_iqn)

        for device in devices:
            if device.ScsiLun == target_lun:
                return device.DeviceNumber

    def get_target_lun_count(self, target_iqn):
        devices = self._get_devices_for_target(target_iqn)
        disk_devices = [device for device in devices
                        if device.DeviceType == self._FILE_DEVICE_DISK]
        return len(disk_devices)

    def get_target_from_disk_path(self, disk_path):
        initiator_sessions = self._conn_wmi.MSiSCSIInitiator_SessionClass()
        drive_number = self._get_drive_number_from_disk_path(disk_path)
        if not drive_number:
            return None

        for initiator_session in initiator_sessions:
            devices = initiator_session.Devices
            for device in devices:
                if device.DeviceNumber == drive_number:
                    return (device.TargetName, device.ScsiLun)
