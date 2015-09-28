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

import os
import shutil
import time

from oslo_log import log as logging

from os_win._i18n import _
from os_win import _utils

LOG = logging.getLogger(__name__)

ERROR_DIR_IS_NOT_EMPTY = 145


class PathUtils(object):
    def open(self, path, mode):
        """Wrapper on __builtin__.open used to simplify unit testing."""
        import __builtin__
        return __builtin__.open(path, mode)

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

    def copy(self, src, dest):
        # With large files this is 2x-3x faster than shutil.copy(src, dest),
        # especially when copying to a UNC target.
        # shutil.copyfileobj(...) with a proper buffer is better than
        # shutil.copy(...) but still 20% slower than a shell copy.
        # It can be replaced with Win32 API calls to avoid the process
        # spawning overhead.
        LOG.debug('Copying file from %s to %s', src, dest)
        output, ret = _utils.execute('cmd.exe', '/C', 'copy', '/Y', src, dest)
        if ret:
            raise IOError(_('The file copy from %(src)s to %(dest)s failed')
                           % {'src': src, 'dest': dest})

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
