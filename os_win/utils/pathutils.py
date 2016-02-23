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

import contextlib
import ctypes
import os
import shutil
import sys
import tempfile
import time

if sys.platform == 'win32':
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32

from oslo_log import log as logging
from oslo_utils import fileutils
import six

from os_win._i18n import _
from os_win import exceptions
from os_win.utils import win32utils

LOG = logging.getLogger(__name__)

ERROR_DIR_IS_NOT_EMPTY = 145


class PathUtils(object):
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x0400

    def __init__(self):
        self._win32_utils = win32utils.Win32Utils()

    def open(self, path, mode):
        """Wrapper on __builtin__.open used to simplify unit testing."""
        from six.moves import builtins
        return builtins.open(path, mode)

    def exists(self, path):
        return os.path.exists(path)

    def makedirs(self, path):
        os.makedirs(path)

    def remove(self, path):
        os.remove(path)

    def rename(self, src, dest):
        os.rename(src, dest)

    def copyfile(self, src, dest):
        self.copy(src, dest)

    def copy(self, src, dest, fail_if_exists=True):
        """Copies a file to a specified location.

        :param fail_if_exists: if set to True, the method fails if the
                               destination path exists.
        """
        # With large files this is 2x-3x faster than shutil.copy(src, dest),
        # especially when copying to a UNC target.
        if os.path.isdir(dest):
            src_fname = os.path.basename(src)
            dest = os.path.join(dest, src_fname)

        try:
            self._win32_utils.run_and_check_output(
                kernel32.CopyFileW,
                ctypes.c_wchar_p(src),
                ctypes.c_wchar_p(dest),
                wintypes.BOOL(fail_if_exists),
                kernel32_lib_func=True)
        except exceptions.Win32Exception as exc:
            err_msg = _('The file copy from %(src)s to %(dest)s failed.'
                        'Exception: %(exc)s')
            raise IOError(err_msg % dict(src=src, dest=dest, exc=exc))

    def move_folder_files(self, src_dir, dest_dir):
        """Moves the files of the given src_dir to dest_dir.
        It will ignore any nested folders.

        :param src_dir: Given folder from which to move files.
        :param dest_dir: Folder to which to move files.
        """

        for fname in os.listdir(src_dir):
            src = os.path.join(src_dir, fname)
            # ignore subdirs.
            if os.path.isfile(src):
                self.rename(src, os.path.join(dest_dir, fname))

    def rmtree(self, path):
        # This will be removed once support for Windows Server 2008R2 is
        # stopped
        for i in range(5):
            try:
                shutil.rmtree(path)
                return
            except WindowsError as e:
                if e.winerror == ERROR_DIR_IS_NOT_EMPTY:
                    time.sleep(1)
                else:
                    raise e

    def check_create_dir(self, path):
        if not self.exists(path):
            LOG.debug('Creating directory: %s', path)
            self.makedirs(path)

    def check_remove_dir(self, path):
        if self.exists(path):
            LOG.debug('Removing directory: %s', path)
            self.rmtree(path)

    def is_symlink(self, path):
        if sys.version_info >= (3, 2):
            return os.path.islink(path)

        file_attr = self._win32_utils.run_and_check_output(
            kernel32.GetFileAttributesW,
            six.text_type(path),
            kernel32_lib_func=True)

        return bool(os.path.isdir(path) and (
            file_attr & self._FILE_ATTRIBUTE_REPARSE_POINT))

    def create_sym_link(self, link, target, target_is_dir=True):
        """If target_is_dir is True, a junction will be created.

        NOTE: Juctions only work on same filesystem.
        """
        create_symlink = kernel32.CreateSymbolicLinkW
        create_symlink.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_ulong,
        )
        create_symlink.restype = ctypes.c_ubyte

        self._win32_utils.run_and_check_output(create_symlink,
                                               link,
                                               target,
                                               target_is_dir,
                                               kernel32_lib_func=True)

    def create_temporary_file(self, suffix=None, *args, **kwargs):
        fd, tmp_file_path = tempfile.mkstemp(suffix=suffix, *args, **kwargs)
        os.close(fd)
        return tmp_file_path

    @contextlib.contextmanager
    def temporary_file(self, suffix=None, *args, **kwargs):
        """Creates a random, temporary, closed file, returning the file's
        path. It's different from tempfile.NamedTemporaryFile which returns
        an open file descriptor.
        """

        tmp_file_path = None
        try:
            tmp_file_path = self.create_temporary_file(suffix, *args, **kwargs)
            yield tmp_file_path
        finally:
            if tmp_file_path:
                fileutils.delete_if_exists(tmp_file_path)
