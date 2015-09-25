# Copyright 2014 Cloudbase Solutions SRL
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

"""
Unit tests for the Hyper-V utils factory.
"""

import mock
from oslo_config import cfg
from oslotest import base

from os_win.utils.compute import vmutils
from os_win.utils.network import networkutils
from os_win.utils.storage.initiator import iscsi_cli_utils
from os_win.utils.storage.initiator import iscsi_wmi_utils
from os_win import utilsfactory

CONF = cfg.CONF


class TestHyperVUtilsFactory(base.BaseTestCase):
    def test_get_vmutils(self):
        actual_class = type(utilsfactory.get_vmutils())
        self.assertEqual(vmutils.VMUtils, actual_class)

    def test_get_networkutils(self):
        self._test_networkutils(expected_class=networkutils.NetworkUtils,
                                os_version='6.2.0')

    def test_get_networkutils_r2(self):
        self._test_networkutils(expected_class=networkutils.NetworkUtilsR2,
                                os_version='6.3.0')

    @mock.patch.object(utilsfactory.utils, 'get_windows_version')
    def _test_networkutils(self, mock_get_win_version, expected_class,
                           os_version):
        mock_get_win_version.return_value = os_version

        actual_class = type(utilsfactory.get_networkutils())
        self.assertEqual(expected_class, actual_class)

    def test_get_iscsi_initiator_utils(self):
        self._test_get_initiator_utils(
            expected_class=iscsi_wmi_utils.ISCSIInitiatorWMIUtils)

    def test_get_iscsi_initiator_utils_force_v1(self):
        self._test_get_initiator_utils(
            expected_class=iscsi_cli_utils.ISCSIInitiatorCLIUtils,
            force_v1=True)

    def _test_get_initiator_utils(self, expected_class, force_v1=False):
        CONF.set_override('force_volumeutils_v1', force_v1, 'hyperv')

        actual_class = type(utilsfactory.get_iscsi_initiator_utils())
        self.assertEqual(expected_class, actual_class)
