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

import mock
from oslotest import base

from os_win import exceptions
from os_win.utils.storage import smbutils


class SMBUtilsTestCase(base.BaseTestCase):
    @mock.patch.object(smbutils, 'wmi', create=True)
    def setUp(self, mock_wmi):
        super(SMBUtilsTestCase, self).setUp()

        self._smbutils = smbutils.SMBUtils()

    @mock.patch.object(smbutils.SMBUtils, 'unmount_smb_share')
    @mock.patch('os.path.exists')
    def _test_check_smb_mapping(self, mock_exists, mock_unmount_smb_share,
                                existing_mappings=True, share_available=False):
        mock_exists.return_value = share_available

        fake_mappings = (
            [mock.sentinel.smb_mapping] if existing_mappings else [])

        self._smbutils._smb_conn.Msft_SmbMapping.return_value = (
            fake_mappings)

        ret_val = self._smbutils.check_smb_mapping(
            mock.sentinel.share_path, remove_unavailable_mapping=True)

        self.assertEqual(existing_mappings and share_available, ret_val)
        if existing_mappings and not share_available:
            mock_unmount_smb_share.assert_called_once_with(
                mock.sentinel.share_path, force=True)

    def test_check_mapping(self):
        self._test_check_smb_mapping()

    def test_remake_unavailable_mapping(self):
        self._test_check_smb_mapping(existing_mappings=True,
                                     share_available=False)

    def test_available_mapping(self):
        self._test_check_smb_mapping(existing_mappings=True,
                                     share_available=True)

    def test_mount_smb_share(self):
        fake_create = self._smbutils._smb_conn.Msft_SmbMapping.Create
        self._smbutils.mount_smb_share(mock.sentinel.share_path,
                                       mock.sentinel.username,
                                       mock.sentinel.password)
        fake_create.assert_called_once_with(
            RemotePath=mock.sentinel.share_path,
            UserName=mock.sentinel.username,
            Password=mock.sentinel.password)

    @mock.patch.object(smbutils, 'wmi', create=True)
    def test_mount_smb_share_failed(self, mock_wmi):
        mock_wmi.x_wmi = Exception
        self._smbutils._smb_conn.Msft_SmbMapping.Create.side_effect = (
            mock_wmi.x_wmi)

        self.assertRaises(exceptions.SMBException,
                          self._smbutils.mount_smb_share,
                          mock.sentinel.share_path)

    def _test_unmount_smb_share(self, force=False):
        fake_mapping = mock.Mock()
        fake_mapping_attr_err = mock.Mock()
        fake_mapping_attr_err.side_effect = AttributeError
        smb_mapping_class = self._smbutils._smb_conn.Msft_SmbMapping
        smb_mapping_class.return_value = [fake_mapping, fake_mapping_attr_err]

        self._smbutils.unmount_smb_share(mock.sentinel.share_path,
                                          force)

        smb_mapping_class.assert_called_once_with(
            RemotePath=mock.sentinel.share_path)
        fake_mapping.Remove.assert_called_once_with(Force=force)

    def test_soft_unmount_smb_share(self):
        self._test_unmount_smb_share()

    def test_force_unmount_smb_share(self):
        self._test_unmount_smb_share(force=True)

    @mock.patch.object(smbutils, 'wmi', create=True)
    def test_unmount_smb_share_wmi_exception(self, mock_wmi):
        mock_wmi.x_wmi = Exception
        fake_mapping = mock.Mock()
        fake_mapping.Remove.side_effect = mock_wmi.x_wmi
        self._smbutils._smb_conn.Msft_SmbMapping.return_value = [fake_mapping]

        self.assertRaises(mock_wmi.x_wmi, self._smbutils.unmount_smb_share,
                          mock.sentinel.share_path, force=True)
