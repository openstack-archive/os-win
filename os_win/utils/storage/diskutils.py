# Copyright 2016 Cloudbase Solutions Srl
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

import collections
import ctypes
import os
import re

from oslo_log import log as logging

from os_win._i18n import _
from os_win import _utils
from os_win import exceptions
from os_win.utils import baseutils
from os_win.utils import win32utils
from os_win.utils.winapi import libs as w_lib

kernel32 = w_lib.get_shared_lib_handle(w_lib.KERNEL32)

LOG = logging.getLogger(__name__)


class DiskUtils(baseutils.BaseUtils):

    _wmi_cimv2_namespace = 'root/cimv2'
    _wmi_storage_namespace = 'root/microsoft/windows/storage'

    def __init__(self):
        self._conn_cimv2 = self._get_wmi_conn(self._wmi_cimv2_namespace)
        self._conn_storage = self._get_wmi_conn(self._wmi_storage_namespace)
        self._win32_utils = win32utils.Win32Utils()

        # Physical device names look like \\.\PHYSICALDRIVE1
        self._phys_dev_name_regex = re.compile(r'\\\\.*\\[a-zA-Z]*([\d]+)')

    def _get_disk_by_number(self, disk_number, msft_disk_cls=True):
        if msft_disk_cls:
            disk = self._conn_storage.Msft_Disk(Number=disk_number)
        else:
            disk = self._conn_cimv2.Win32_DiskDrive(Index=disk_number)

        if not disk:
            err_msg = _("Could not find the disk number %s")
            raise exceptions.DiskNotFound(err_msg % disk_number)
        return disk[0]

    def _get_disks_by_unique_id(self, unique_id, unique_id_format):
        # In some cases, multiple disks having the same unique id may be
        # exposed to the OS. This may happen if there are multiple paths
        # to the LUN and MPIO is not properly configured. This can be
        # valuable information to the caller.
        disks = self._conn_storage.Msft_Disk(UniqueId=unique_id,
                                             UniqueIdFormat=unique_id_format)
        if not disks:
            err_msg = _("Could not find any disk having unique id "
                        "'%(unique_id)s' and unique id format "
                        "'%(unique_id_format)s'")
            raise exceptions.DiskNotFound(err_msg % dict(
                unique_id=unique_id,
                unique_id_format=unique_id_format))
        return disks

    def get_disk_numbers_by_unique_id(self, unique_id, unique_id_format):
        disks = self._get_disks_by_unique_id(unique_id, unique_id_format)
        return [disk.Number for disk in disks]

    def get_disk_uid_and_uid_type(self, disk_number):
        disk = self._get_disk_by_number(disk_number)
        return disk.UniqueId, disk.UniqueIdFormat

    def is_mpio_disk(self, disk_number):
        disk = self._get_disk_by_number(disk_number)
        return disk.Path.lower().startswith(r'\\?\mpio')

    def refresh_disk(self, disk_number):
        disk = self._get_disk_by_number(disk_number)
        disk.Refresh()

    def get_device_name_by_device_number(self, device_number):
        disk = self._get_disk_by_number(device_number,
                                        msft_disk_cls=False)
        return disk.Name

    def get_device_number_from_device_name(self, device_name):
        matches = self._phys_dev_name_regex.findall(device_name)
        if matches:
            return matches[0]

        err_msg = _("Could not find device number for device: %s")
        raise exceptions.DiskNotFound(err_msg % device_name)

    @_utils.retry_decorator(exceptions=(exceptions.x_wmi,
                                        exceptions.OSWinException))
    def rescan_disks(self):
        ret = self._conn_storage.Msft_StorageSetting.UpdateHostStorageCache()

        if isinstance(ret, collections.Iterable):
            ret = ret[0]

        if ret:
            err_msg = _("Rescanning disks failed. Error code: %s.")
            raise exceptions.OSWinException(err_msg % ret)

    def get_disk_capacity(self, path, ignore_errors=False):
        norm_path = os.path.abspath(path)

        total_bytes = ctypes.c_ulonglong(0)
        free_bytes = ctypes.c_ulonglong(0)

        try:
            self._win32_utils.run_and_check_output(
                kernel32.GetDiskFreeSpaceExW,
                ctypes.c_wchar_p(norm_path),
                None,
                ctypes.pointer(total_bytes),
                ctypes.pointer(free_bytes),
                kernel32_lib_func=True)
            return total_bytes.value, free_bytes.value
        except exceptions.Win32Exception as exc:
            LOG.error("Could not get disk %(path)s capacity info. "
                      "Exception: %(exc)s",
                      dict(path=path,
                           exc=exc))
            if ignore_errors:
                return 0, 0
            else:
                raise exc
