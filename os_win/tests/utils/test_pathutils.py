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

from os_win.utils import pathutils


class PathUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V PathUtils class."""

    def setUp(self):
        super(PathUtilsTestCase, self).setUp()
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

    @mock.patch.object(pathutils.PathUtils, 'makedirs')
    @mock.patch.object(pathutils.PathUtils, 'exists')
    def test_check_create_dir(self, mock_exists, mock_makedirs):
        fake_dir = 'dir'
        mock_exists.return_value = False
        self._pathutils.check_create_dir(fake_dir)

        mock_exists.assert_called_once_with(fake_dir)
        mock_makedirs.assert_called_once_with(fake_dir)

    @mock.patch.object(pathutils.PathUtils, 'rmtree')
    @mock.patch.object(pathutils.PathUtils, 'exists')
    def test_check_remove_dir(self, mock_exists, mock_rmtree):
        fake_dir = 'dir'
        self._pathutils.check_remove_dir(fake_dir)

        mock_exists.assert_called_once_with(fake_dir)
        mock_rmtree.assert_called_once_with(fake_dir)
