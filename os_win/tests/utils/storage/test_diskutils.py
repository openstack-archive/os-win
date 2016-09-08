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

import ddt
import mock

from os_win import exceptions
from os_win.tests import test_base
from os_win.utils.storage import diskutils


@ddt.ddt
class DiskUtilsTestCase(test_base.OsWinBaseTestCase):
    def setUp(self):
        super(DiskUtilsTestCase, self).setUp()
        self._diskutils = diskutils.DiskUtils()
        self._diskutils._conn_storage = mock.MagicMock()
        self._diskutils._win32_utils = mock.MagicMock()
        self._mock_run = self._diskutils._win32_utils.run_and_check_output

    def test_get_disk(self):
        mock_msft_disk_cls = self._diskutils._conn_storage.Msft_Disk
        mock_disk = mock_msft_disk_cls.return_value[0]

        resulted_disk = self._diskutils._get_disk(mock.sentinel.disk_number)

        mock_msft_disk_cls.assert_called_once_with(
            Number=mock.sentinel.disk_number)
        self.assertEqual(mock_disk, resulted_disk)

    def test_get_unexisting_disk(self):
        mock_msft_disk_cls = self._diskutils._conn_storage.Msft_Disk
        mock_msft_disk_cls.return_value = []

        self.assertRaises(exceptions.DiskNotFound,
                          self._diskutils._get_disk,
                          mock.sentinel.disk_number)

        mock_msft_disk_cls.assert_called_once_with(
            Number=mock.sentinel.disk_number)

    @mock.patch.object(diskutils.DiskUtils, '_get_disk')
    def test_get_disk_uid_and_uid_type(self, mock_get_disk):
        mock_disk = mock_get_disk.return_value

        uid, uid_type = self._diskutils.get_disk_uid_and_uid_type(
            mock.sentinel.disk_number)

        mock_get_disk.assert_called_once_with(mock.sentinel.disk_number)
        self.assertEqual(mock_disk.UniqueId, uid)
        self.assertEqual(mock_disk.UniqueIdFormat, uid_type)

    def test_get_disk_uid_and_uid_type_not_found(self):
        mock_msft_disk_cls = self._diskutils._conn_storage.Msft_Disk
        mock_msft_disk_cls.return_value = []

        self.assertRaises(exceptions.DiskNotFound,
                          self._diskutils.get_disk_uid_and_uid_type,
                          mock.sentinel.disk_number)

    @mock.patch.object(diskutils.DiskUtils, '_get_disk')
    def test_refresh_disk(self, mock_get_disk):
        mock_disk = mock_get_disk.return_value

        self._diskutils.refresh_disk(mock.sentinel.disk_number)

        mock_get_disk.assert_called_once_with(mock.sentinel.disk_number)
        mock_disk.Refresh.assert_called_once_with()

    def test_get_dev_number_from_dev_name(self):
        fake_physical_device_name = r'\\.\PhysicalDrive15'
        expected_device_number = '15'

        get_dev_number = self._diskutils.get_device_number_from_device_name
        resulted_dev_number = get_dev_number(fake_physical_device_name)
        self.assertEqual(expected_device_number, resulted_dev_number)

    def test_get_device_number_from_invalid_device_name(self):
        fake_physical_device_name = ''

        self.assertRaises(exceptions.DiskNotFound,
                          self._diskutils.get_device_number_from_device_name,
                          fake_physical_device_name)

    def _get_mocked_wmi_rescan(self, return_value):
        conn = self._diskutils._conn_storage
        rescan_method = conn.Msft_StorageSetting.UpdateHostStorageCache
        rescan_method.return_value = return_value
        return rescan_method

    @ddt.data(0, [0], (0,))
    @mock.patch('time.sleep')
    def test_rescan_disks(self, return_value, mock_sleep):
        mock_rescan = self._get_mocked_wmi_rescan(return_value)

        self._diskutils.rescan_disks()

        mock_rescan.assert_called_once_with()

    @mock.patch('time.sleep')
    def test_rescan_disks_error(self, mock_sleep):
        mock_rescan = self._get_mocked_wmi_rescan(return_value=1)
        expected_retry_count = 5

        self.assertRaises(exceptions.OSWinException,
                          self._diskutils.rescan_disks)
        mock_rescan.assert_has_calls([mock.call()] * expected_retry_count)

    @mock.patch.object(diskutils, 'ctypes')
    @mock.patch.object(diskutils, 'kernel32', create=True)
    @mock.patch('os.path.abspath')
    def _test_get_disk_capacity(self, mock_abspath,
                                mock_kernel32, mock_ctypes,
                                raised_exc=None, ignore_errors=False):
        expected_values = ('total_bytes', 'free_bytes')

        mock_params = [mock.Mock(value=value) for value in expected_values]
        mock_ctypes.c_ulonglong.side_effect = mock_params
        mock_ctypes.c_wchar_p = lambda x: (x, 'c_wchar_p')

        self._mock_run.side_effect = raised_exc(
            func_name='fake_func_name',
            error_code='fake_error_code',
            error_message='fake_error_message') if raised_exc else None

        if raised_exc and not ignore_errors:
            self.assertRaises(raised_exc,
                              self._diskutils.get_disk_capacity,
                              mock.sentinel.disk_path,
                              ignore_errors=ignore_errors)
        else:
            ret_val = self._diskutils.get_disk_capacity(
                mock.sentinel.disk_path,
                ignore_errors=ignore_errors)
            expected_ret_val = (0, 0) if raised_exc else expected_values

            self.assertEqual(expected_ret_val, ret_val)

        mock_abspath.assert_called_once_with(mock.sentinel.disk_path)
        mock_ctypes.pointer.assert_has_calls(
            [mock.call(param) for param in mock_params])
        self._mock_run.assert_called_once_with(
            mock_kernel32.GetDiskFreeSpaceExW,
            mock_ctypes.c_wchar_p(mock_abspath.return_value),
            None,
            mock_ctypes.pointer.return_value,
            mock_ctypes.pointer.return_value,
            kernel32_lib_func=True)

    def test_get_disk_capacity_successfully(self):
        self._test_get_disk_capacity()

    def test_get_disk_capacity_ignored_error(self):
        self._test_get_disk_capacity(
            raised_exc=exceptions.Win32Exception,
            ignore_errors=True)

    def test_get_disk_capacity_raised_exc(self):
        self._test_get_disk_capacity(
            raised_exc=exceptions.Win32Exception)
