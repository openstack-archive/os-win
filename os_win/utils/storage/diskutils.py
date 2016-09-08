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
import sys

from oslo_log import log as logging

from os_win._i18n import _, _LE
from os_win import _utils
from os_win import exceptions
from os_win.utils import baseutils
from os_win.utils import win32utils

if sys.platform == 'win32':
    kernel32 = ctypes.windll.kernel32

LOG = logging.getLogger(__name__)


class DiskUtils(baseutils.BaseUtils):

    _wmi_namespace = 'root/microsoft/windows/storage'

    def __init__(self):
        self._conn_storage = self._get_wmi_conn(self._wmi_namespace)
        self._win32_utils = win32utils.Win32Utils()

        # Physical device names look like \\.\PHYSICALDRIVE1
        self._phys_dev_name_regex = re.compile(r'\\\\.*\\[a-zA-Z]*([\d]+)')

    def _get_disk(self, disk_number):
        disk = self._conn_storage.Msft_Disk(Number=disk_number)
        if not disk:
            err_msg = _("Could not find the disk number %s")
            raise exceptions.DiskNotFound(err_msg % disk_number)
        return disk[0]

    def get_disk_uid_and_uid_type(self, disk_number):
        disk = self._get_disk(disk_number)
        return disk.UniqueId, disk.UniqueIdFormat

    def refresh_disk(self, disk_number):
        disk = self._get_disk(disk_number)
        disk.Refresh()

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
            LOG.error(_LE("Could not get disk %(path)s capacity info. "
                          "Exception: %(exc)s"),
                      dict(path=path,
                           exc=exc))
            if ignore_errors:
                return 0, 0
            else:
                raise exc
