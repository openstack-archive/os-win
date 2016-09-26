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

import ctypes
import sys

from os_win.utils import win32utils

if sys.platform == 'win32':
    advapi = ctypes.windll.AdvApi32


OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SACL_SECURITY_INFORMATION = 0x00000008

# Trustee form constants
TRUSTEE_IS_NAME = 1

# Indicates a file or directory object.
SE_FILE_OBJECT = 1


class TRUSTEE(ctypes.Structure):
    _fields_ = [('pMultipleTrustee', ctypes.c_void_p),
                ('MultipleTrusteeOperation', ctypes.c_uint),
                ('TrusteeForm', ctypes.c_uint),
                ('TrusteeType', ctypes.c_uint),
                ('pstrName', ctypes.c_wchar_p)]


class EXPLICIT_ACCESS(ctypes.Structure):
    _fields_ = [('grfAccessPermissions', ctypes.c_ulong),
                ('grfAccessMode', ctypes.c_uint),
                ('grfInheritance', ctypes.c_ulong),
                ('Trustee', TRUSTEE)]


class ACLUtils(object):
    def __init__(self):
        self._win32_utils = win32utils.Win32Utils()

    @staticmethod
    def _get_void_pp():
        return ctypes.pointer(ctypes.c_void_p())

    def get_named_security_info(self, obj_name, obj_type, security_info_flags):
        """Retrieve object security information.

        :param security_info_flags: specifies which informations will
                                   be retrieved.
        :param ret_val: dict, containing pointers to the requested structures.
                        Note that the returned security descriptor will have
                        to be freed using LocalFree.
                        Some requested information may not be present, in
                        which case the according pointers will be NULL.
        """
        sec_info = {}

        if security_info_flags & OWNER_SECURITY_INFORMATION:
            sec_info['pp_sid_owner'] = self._get_void_pp()
        if security_info_flags & GROUP_SECURITY_INFORMATION:
            sec_info['pp_sid_group'] = self._get_void_pp()
        if security_info_flags & DACL_SECURITY_INFORMATION:
            sec_info['pp_dacl'] = self._get_void_pp()
        if security_info_flags & SACL_SECURITY_INFORMATION:
            sec_info['pp_sacl'] = self._get_void_pp()
        sec_info['pp_sec_desc'] = self._get_void_pp()

        self._win32_utils.run_and_check_output(
            advapi.GetNamedSecurityInfoW,
            ctypes.c_wchar_p(obj_name),
            ctypes.c_uint(obj_type),
            ctypes.c_uint(security_info_flags),
            sec_info.get('pp_sid_owner'),
            sec_info.get('pp_sid_group'),
            sec_info.get('pp_dacl'),
            sec_info.get('pp_sacl'),
            sec_info['pp_sec_desc'])

        return sec_info

    def set_entries_in_acl(self, entry_count, p_explicit_entry_list,
                           p_old_acl):
        """Merge new ACEs into an existing ACL, returing a new ACL."""
        pp_new_acl = self._get_void_pp()

        self._win32_utils.run_and_check_output(
            advapi.SetEntriesInAclW,
            ctypes.c_ulong(entry_count),
            p_explicit_entry_list,
            p_old_acl,
            pp_new_acl)

        return pp_new_acl

    def set_named_security_info(self, obj_name, obj_type, security_info_flags,
                                p_sid_owner=None, p_sid_group=None,
                                p_dacl=None, p_sacl=None):
        self._win32_utils.run_and_check_output(
            advapi.SetNamedSecurityInfoW,
            ctypes.c_wchar_p(obj_name),
            ctypes.c_uint(obj_type),
            ctypes.c_uint(security_info_flags),
            p_sid_owner,
            p_sid_group,
            p_dacl,
            p_sacl)
