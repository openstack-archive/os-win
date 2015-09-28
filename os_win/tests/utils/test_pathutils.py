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
from os_win.utils import pathutils


class PathUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V PathUtils class."""

    def setUp(self):
        super(PathUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        self._pathutils = pathutils.PathUtils()
        self._pathutils._win32_utils = mock.Mock()
        self._mock_run = self._pathutils._win32_utils.run_and_check_output

        self.addCleanup(mock.patch.stopall)

    def _setup_lib_mocks(self):
        self._ctypes = mock.Mock()
        self._wintypes = mock.Mock()

        self._wintypes.BOOL = lambda x: (x, 'BOOL')
        self._ctypes.c_wchar_p = lambda x: (x, "c_wchar_p")

        mock.patch.multiple(pathutils,
                            wintypes=self._wintypes,
                            ctypes=self._ctypes, kernel32=mock.DEFAULT,
                            create=True).start()

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

    @mock.patch('os.path.isdir')
    @mock.patch('os.path.islink')
    def _test_check_symlink(self, mock_is_symlink, mock_is_dir,
                            is_symlink=True, python_version=(2, 7),
                            is_dir=True):
        fake_path = r'c:\\fake_path'
        if is_symlink:
            f_attr = 0x400
        else:
            f_attr = 0x80

        mock_is_dir.return_value = is_dir
        mock_is_symlink.return_value = is_symlink
        self._mock_run.return_value = f_attr

        with mock.patch('sys.version_info', python_version):
            ret_value = self._pathutils.is_symlink(fake_path)

        if python_version >= (3, 2):
            mock_is_symlink.assert_called_once_with(fake_path)
        else:
            self._mock_run.assert_called_once_with(
                pathutils.kernel32.GetFileAttributesW,
                fake_path,
                kernel32_lib_func=True)

        self.assertEqual(is_symlink, ret_value)

    def test_is_symlink(self):
        self._test_check_symlink()

    def test_is_not_symlink(self):
        self._test_check_symlink(is_symlink=False)

    def test_is_symlink_python_gt_3_2(self):
        self._test_check_symlink(python_version=(3, 3))

    def test_create_sym_link(self):
        tg_is_dir = False
        self._pathutils.create_sym_link(mock.sentinel.path,
                                        mock.sentinel.target,
                                        target_is_dir=tg_is_dir)

        self._mock_run.assert_called_once_with(
            pathutils.kernel32.CreateSymbolicLinkW,
            mock.sentinel.path,
            mock.sentinel.target,
            tg_is_dir,
            kernel32_lib_func=True)

    @mock.patch('os.path.isdir')
    def _test_copy(self, mock_isdir, dest_isdir=False):
        mock_isdir.return_value = dest_isdir
        fail_if_exists = False

        fake_src = r'fake_src_fname'
        fake_dest = r'fake_dest'

        expected_dest = (os.path.join(fake_dest, fake_src)
                         if dest_isdir else fake_dest)

        self._pathutils.copy(fake_src, fake_dest,
                             fail_if_exists=fail_if_exists)

        self._mock_run.assert_called_once_with(
            pathutils.kernel32.CopyFileW,
            self._ctypes.c_wchar_p(fake_src),
            self._ctypes.c_wchar_p(expected_dest),
            self._wintypes.BOOL(fail_if_exists),
            kernel32_lib_func=True)

    def test_copy_dest_is_fpath(self):
        self._test_copy()

    def test_copy_dest_is_dir(self):
        self._test_copy(dest_isdir=True)

    @mock.patch('os.path.isdir')
    def test_copy_exc(self, mock_isdir):
        mock_isdir.return_value = False
        self._mock_run.side_effect = exceptions.Win32Exception(
            func_name='mock_copy',
            error_code='fake_error_code',
            error_message='fake_error_msg')
        self.assertRaises(IOError,
                          self._pathutils.copy,
                          mock.sentinel.src,
                          mock.sentinel.dest)
