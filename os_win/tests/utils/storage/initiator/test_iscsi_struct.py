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

import six

from os_win import constants
from os_win.tests import test_base
from os_win.utils.storage.initiator import iscsidsc_structures as iscsi_struct


class ISCSIStructTestCase(test_base.OsWinBaseTestCase):
    def test_iscsi_login_opts_setup(self):
        fake_username = 'fake_chap_username'
        fake_password = 'fake_chap_secret'
        auth_type = constants.ISCSI_CHAP_AUTH_TYPE

        login_opts = iscsi_struct.ISCSI_LOGIN_OPTIONS(Username=fake_username,
                                                      Password=fake_password,
                                                      AuthType=auth_type)

        self.assertIsInstance(login_opts.Username, iscsi_struct.PUCHAR)
        self.assertIsInstance(login_opts.Password, iscsi_struct.PUCHAR)

        self.assertEqual(len(fake_username), login_opts.UsernameLength)
        self.assertEqual(len(fake_password), login_opts.PasswordLength)

        username_struct_contents = ctypes.cast(
            login_opts.Username,
            ctypes.POINTER(ctypes.c_char * len(fake_username))).contents.value
        pwd_struct_contents = ctypes.cast(
            login_opts.Password,
            ctypes.POINTER(ctypes.c_char * len(fake_password))).contents.value

        self.assertEqual(six.b(fake_username), username_struct_contents)
        self.assertEqual(six.b(fake_password), pwd_struct_contents)

        expected_info_bitmap = (iscsi_struct.ISCSI_LOGIN_OPTIONS_USERNAME |
                                iscsi_struct.ISCSI_LOGIN_OPTIONS_PASSWORD |
                                iscsi_struct.ISCSI_LOGIN_OPTIONS_AUTH_TYPE)
        self.assertEqual(expected_info_bitmap,
                         login_opts.InformationSpecified)
