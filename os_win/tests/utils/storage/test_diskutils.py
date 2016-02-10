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

import mock

from os_win import _utils
from os_win import exceptions
from os_win.tests import test_base
from os_win.utils.storage import diskutils


class DiskUtilsTestCase(test_base.OsWinBaseTestCase):
    def setUp(self):
        super(DiskUtilsTestCase, self).setUp()
        self._diskutils = diskutils.DiskUtils()
        self._diskutils._conn_storage = mock.MagicMock()

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

    @mock.patch.object(_utils, 'execute')
    def test_rescan_disks(self, mock_execute):
        cmd = ("cmd", "/c", "echo", "rescan", "|", "diskpart.exe")

        self._diskutils.rescan_disks()

        mock_execute.assert_called_once_with(*cmd)
