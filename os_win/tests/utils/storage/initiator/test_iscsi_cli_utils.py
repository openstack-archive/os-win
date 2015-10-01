#  Copyright 2014 Cloudbase Solutions Srl
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

import mock
from oslotest import base

from os_win import exceptions
from os_win.utils.storage.initiator import iscsi_cli_utils


class ISCSIInitiatorCLIUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V ISCSIInitiatorCLIUtils class."""

    _FAKE_PORTAL_ADDR = '10.1.1.1'
    _FAKE_PORTAL_PORT = '3260'
    _FAKE_LUN = 0
    _FAKE_TARGET = 'iqn.2010-10.org.openstack:fake_target'

    _FAKE_STDOUT_VALUE = 'The operation completed successfully'

    def setUp(self):
        super(ISCSIInitiatorCLIUtilsTestCase, self).setUp()
        self._initiator = iscsi_cli_utils.ISCSIInitiatorCLIUtils()
        self._initiator._conn_wmi = mock.MagicMock()
        self._initiator._conn_cimv2 = mock.MagicMock()

    def _test_login_target_portal(self, portal_connected):
        fake_portal = '%s:%s' % (self._FAKE_PORTAL_ADDR,
                                 self._FAKE_PORTAL_PORT)

        self._initiator.execute = mock.MagicMock()
        if portal_connected:
            exec_output = 'Address and Socket: %s %s' % (
                self._FAKE_PORTAL_ADDR, self._FAKE_PORTAL_PORT)
        else:
            exec_output = ''

        self._initiator.execute.return_value = exec_output

        self._initiator._login_target_portal(fake_portal)

        call_list = self._initiator.execute.call_args_list
        all_call_args = [arg for call in call_list for arg in call[0]]

        if portal_connected:
            self.assertIn('RefreshTargetPortal', all_call_args)
        else:
            self.assertIn('AddTargetPortal', all_call_args)

    def test_login_connected_portal(self):
        self._test_login_target_portal(True)

    def test_login_new_portal(self):
        self._test_login_target_portal(False)

    @mock.patch.object(iscsi_cli_utils, 'CONF')
    def _test_login_target(self, mock_CONF, target_connected=False,
                           raise_exception=False, use_chap=False):
        mock_CONF.hyperv.volume_attach_retry_count = 4
        mock_CONF.hyperv.volume_attach_retry_interval = 0
        fake_portal = '%s:%s' % (self._FAKE_PORTAL_ADDR,
                                 self._FAKE_PORTAL_PORT)
        self._initiator.execute = mock.MagicMock()
        self._initiator._login_target_portal = mock.MagicMock()

        if use_chap:
            username, password = (mock.sentinel.username,
                                  mock.sentinel.password)
        else:
            username, password = None, None

        if target_connected:
            self._initiator.execute.return_value = self._FAKE_TARGET
        elif raise_exception:
            self._initiator.execute.return_value = ''
        else:
            self._initiator.execute.side_effect = (
                ['', '', '', self._FAKE_TARGET, ''])

        if raise_exception:
            self.assertRaises(exceptions.HyperVException,
                              self._initiator.login_storage_target,
                              self._FAKE_LUN, self._FAKE_TARGET,
                              fake_portal, username, password)
        else:
            self._initiator.login_storage_target(self._FAKE_LUN,
                                                self._FAKE_TARGET,
                                                fake_portal,
                                                username, password)

            if target_connected:
                call_list = self._initiator.execute.call_args_list
                all_call_args = [arg for call in call_list for arg in call[0]]
                self.assertNotIn('qlogintarget', all_call_args)
            else:
                self._initiator.execute.assert_any_call(
                    'iscsicli.exe', 'qlogintarget',
                    self._FAKE_TARGET, username, password)

    def test_login_connected_target(self):
        self._test_login_target(target_connected=True)

    def test_login_disconncted_target(self):
        self._test_login_target()

    def test_login_target_exception(self):
        self._test_login_target(raise_exception=True)

    def test_login_target_using_chap(self):
        self._test_login_target(use_chap=True)

    def _test_execute_wrapper(self, raise_exception):
        fake_cmd = ('iscsicli.exe', 'ListTargetPortals')

        if raise_exception:
            output = 'fake error'
        else:
            output = 'The operation completed successfully'

        with mock.patch('os_win._utils.execute') as fake_execute:
            fake_execute.return_value = (output, None)

            if raise_exception:
                self.assertRaises(exceptions.HyperVException,
                                  self._initiator.execute,
                                  *fake_cmd)
            else:
                ret_val = self._initiator.execute(*fake_cmd)
                self.assertEqual(output, ret_val)

    def test_execute_raise_exception(self):
        self._test_execute_wrapper(True)

    def test_execute_exception(self):
        self._test_execute_wrapper(False)

    @mock.patch.object(iscsi_cli_utils, '_utils')
    def test_logout_storage_target(self, mock_utils):
        mock_utils.execute.return_value = (self._FAKE_STDOUT_VALUE,
                                           mock.sentinel.FAKE_STDERR_VALUE)
        session = mock.MagicMock()
        session.SessionId = mock.sentinel.FAKE_SESSION_ID
        self._initiator._conn_wmi.query.return_value = [session]

        self._initiator.logout_storage_target(mock.sentinel.FAKE_IQN)
        mock_utils.execute.assert_called_once_with(
            'iscsicli.exe', 'logouttarget', mock.sentinel.FAKE_SESSION_ID)
