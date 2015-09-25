# Copyright 2015 Cloudbase Solutions Srl
#
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

import ctypes
import sys

if sys.platform == 'win32':
    kernel32 = ctypes.windll.kernel32

from oslo_log import log as logging

from os_win import exceptions

LOG = logging.getLogger(__name__)

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200


class Win32Utils(object):
    def __init__(self):
        self._kernel32_lib_func_opts = dict(error_ret_vals=[0],
                                            error_on_nonzero_ret_val=False,
                                            ret_val_is_err_code=False)

    def run_and_check_output(self, func, *args, **kwargs):
        """Convenience helper method for running Win32 API methods."""
        kernel32_lib_func = kwargs.pop('kernel32_lib_func', False)
        if kernel32_lib_func:
            kwargs.update(self._kernel32_lib_func_opts)

        ignored_error_codes = kwargs.pop('ignored_error_codes', [])

        # A list of return values signaling that the operation failed.
        error_ret_vals = kwargs.pop('error_ret_vals', [])
        error_on_nonzero_ret_val = kwargs.pop('error_on_nonzero_ret_val', True)
        ret_val_is_err_code = kwargs.pop('ret_val_is_err_code', True)

        # The exception raised when the Win32 API function fails. The
        # exception must inherit Win32Exception.
        failure_exc = kwargs.pop('failure_exc', exceptions.Win32Exception)

        ret_val = func(*args, **kwargs)

        func_failed = (error_on_nonzero_ret_val and ret_val) or (
                       ret_val in error_ret_vals)

        if func_failed:
            error_code = (ret_val
                          if ret_val_is_err_code else self.get_last_error())
            if error_code not in ignored_error_codes:
                error_message = self.get_error_message(error_code)
                func_name = getattr(func, '__name__', '')
                raise failure_exc(error_code=error_code,
                                  error_message=error_message,
                                  func_name=func_name)
        return ret_val

    @staticmethod
    def get_error_message(error_code):
        message_buffer = ctypes.c_char_p()

        kernel32.FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            None, error_code, 0, ctypes.byref(message_buffer), 0, None)

        error_message = message_buffer.value
        kernel32.LocalFree(message_buffer)
        return error_message

    def get_last_error(self):
        error_code = kernel32.GetLastError()
        kernel32.SetLastError(0)
        return error_code

    @staticmethod
    def hresult_to_err_code(hresult):
        # The last 2 bytes of the hresult store the error code.
        return hresult & 0xFF

    def get_com_err_code(self, com_error):
        hres = None
        try:
            hres = com_error.excepinfo[5]
        except Exception:
            LOG.debug("Unable to retrieve COM error hresult: %s", com_error)

        if hres is not None:
            return self.hresult_to_err_code(hres)
