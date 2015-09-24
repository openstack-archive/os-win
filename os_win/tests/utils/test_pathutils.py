#  Copyright 2014 IBM Corp.
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

import os

import mock
from oslotest import base

from os_win import exceptions
from os_win.utils import constants
from os_win.utils import pathutils


class PathUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V PathUtils class."""

    def setUp(self):
        super(PathUtilsTestCase, self).setUp()
        self.fake_instance_dir = os.path.join('C:', 'fake_instance_dir')
        self.fake_instance_name = 'fake_instance_name'

        self._pathutils = pathutils.PathUtils()

    @mock.patch.object(pathutils.PathUtils, 'rename')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os, 'listdir')
    def test_move_folder_files(self, mock_listdir, mock_isfile, mock_rename):
        src_dir = 'src'
        dest_dir = 'dest'
        fname = 'tmp_file.txt'
        subdir = 'tmp_folder'
        src_fname = os.path.join(src_dir, fname)
        dest_fname = os.path.join(dest_dir, fname)

        # making sure src_subdir is not moved.
        mock_listdir.return_value = [fname, subdir]
        mock_isfile.side_effect = [True, False]

        self._pathutils.move_folder_files(src_dir, dest_dir)
        mock_rename.assert_called_once_with(src_fname, dest_fname)

    def _mock_lookup_configdrive_path(self, ext):
        self._pathutils.get_instance_dir = mock.MagicMock(
            return_value=self.fake_instance_dir)

        def mock_exists(*args, **kwargs):
            path = args[0]
            return True if path[(path.rfind('.') + 1):] == ext else False
        self._pathutils.exists = mock_exists
        configdrive_path = self._pathutils.lookup_configdrive_path(
            self.fake_instance_name)
        return configdrive_path

    def test_lookup_configdrive_path(self):
        for format_ext in constants.DISK_FORMAT_MAP:
            configdrive_path = self._mock_lookup_configdrive_path(format_ext)
            fake_path = os.path.join(self.fake_instance_dir,
                                     'configdrive.' + format_ext)
            self.assertEqual(configdrive_path, fake_path)

    def test_lookup_configdrive_path_non_exist(self):
        self._pathutils.get_instance_dir = mock.MagicMock(
            return_value=self.fake_instance_dir)
        self._pathutils.exists = mock.MagicMock(return_value=False)
        configdrive_path = self._pathutils.lookup_configdrive_path(
            self.fake_instance_name)
        self.assertIsNone(configdrive_path)

    @mock.patch('shutil.rmtree')
    @mock.patch('time.sleep')
    def test_rmtree(self, mock_sleep, mock_rmtree):
        class WindowsError(Exception):
            def __init__(self, winerror=None):
                self.winerror = winerror

        mock_rmtree.side_effect = [WindowsError(
            pathutils.ERROR_DIR_IS_NOT_EMPTY), True]
        fake_windows_error = WindowsError
        with mock.patch('__builtin__.WindowsError',
                        fake_windows_error, create=True):
            self._pathutils.rmtree(mock.sentinel.FAKE_PATH)

        mock_sleep.assert_called_once_with(1)
        mock_rmtree.assert_has_calls([mock.call(mock.sentinel.FAKE_PATH),
                                      mock.call(mock.sentinel.FAKE_PATH)])

    @mock.patch.object(pathutils, 'CONF')
    @mock.patch('os.path.join')
    def test_get_instances_sub_dir(self, fake_path_join, mock_conf):
        mock_conf.hyperv.instances_dir = '\\'

        class WindowsError(Exception):
            def __init__(self, winerror=None):
                self.winerror = winerror

        fake_dir_name = "fake_dir_name"
        fake_windows_error = WindowsError
        self._pathutils._check_create_dir = mock.MagicMock(
            side_effect=WindowsError(pathutils.ERROR_INVALID_NAME))
        with mock.patch('__builtin__.WindowsError',
                        fake_windows_error, create=True):
            self.assertRaises(exceptions.HyperVException,
                              self._pathutils._get_instances_sub_dir,
                              fake_dir_name)
