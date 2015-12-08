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

from os_win import exceptions
from os_win.utils.compute import livemigrationutils
from os_win.utils.compute import rdpconsoleutils
from os_win.utils.compute import vmutils
from os_win.utils import hostutils
from os_win.utils.network import networkutils
from os_win.utils import pathutils
from os_win.utils.storage.initiator import iscsi_cli_utils
from os_win.utils.storage.initiator import iscsi_wmi_utils
from os_win.utils.storage import smbutils
from os_win.utils.storage.virtdisk import vhdutils
from os_win import utilsfactory

CONF = cfg.CONF


class TestHyperVUtilsFactory(base.BaseTestCase):

    @mock.patch.object(utilsfactory.utils, 'get_windows_version')
    def test_get_class_unsupported_win_version(self, mock_get_windows_version):
        mock_get_windows_version.return_value = '5.2'
        self.assertRaises(exceptions.HyperVException, utilsfactory._get_class,
                          'hostutils')

    def test_get_class_unsupported_class_type(self):
        self.assertRaises(exceptions.HyperVException,
                          utilsfactory._get_class,
                          'invalid_class_type')

    @mock.patch.object(utilsfactory.utils, 'get_windows_version')
    def _check_get_class(self, mock_get_windows_version, expected_class,
                       class_type):
        mock_get_windows_version.return_value = '6.2'

        method = getattr(utilsfactory, 'get_%s' % class_type)
        instance = method()
        self.assertEqual(expected_class, type(instance))

    def test_get_vmutils(self):
        self._check_get_class(expected_class=vmutils.VMUtils,
                              class_type='vmutils')

    def test_get_vhdutils(self):
        self._check_get_class(expected_class=vhdutils.VHDUtils,
                              class_type='vhdutils')

    def test_get_networkutils(self):
        self._check_get_class(expected_class=networkutils.NetworkUtils,
                              class_type='networkutils')

    def test_get_hostutils(self):
        self._check_get_class(expected_class=hostutils.HostUtils,
                              class_type='hostutils')

    def test_get_pathutils(self):
        self._check_get_class(expected_class=pathutils.PathUtils,
                              class_type='pathutils')

    def test_get_livemigrationutils(self):
        self._check_get_class(
            expected_class=livemigrationutils.LiveMigrationUtils,
            class_type='livemigrationutils')

    @mock.patch.object(smbutils.SMBUtils, '__init__',
                       lambda *args, **kwargs: None)
    def test_get_smbutils(self):
        self._check_get_class(expected_class=smbutils.SMBUtils,
                              class_type='smbutils')

    def test_get_rdpconsoleutils(self):
        self._check_get_class(expected_class=rdpconsoleutils.RDPConsoleUtils,
                              class_type='rdpconsoleutils')

    def test_get_iscsi_initiator_utils(self):
        self._test_get_initiator_utils(
            expected_class=iscsi_wmi_utils.ISCSIInitiatorWMIUtils)

    def test_get_iscsi_initiator_utils_force_v1(self):
        self._test_get_initiator_utils(
            expected_class=iscsi_cli_utils.ISCSIInitiatorCLIUtils,
            force_v1=True)

    @mock.patch.object(utilsfactory.utils, 'get_windows_version')
    def _test_get_initiator_utils(self, mock_get_windows_version,
                                  expected_class, force_v1=False):
        CONF.set_override('force_volumeutils_v1', force_v1, 'hyperv')
        mock_get_windows_version.return_value = '6.2'

        actual_class = type(utilsfactory.get_iscsi_initiator_utils())
        self.assertEqual(expected_class, actual_class)

    @mock.patch('os_win.utils.storage.initiator.fc_utils.FCUtils')
    def test_get_fc_utils(self, mock_cls_fcutils):
        self._check_get_class(
            expected_class=type(mock_cls_fcutils.return_value),
            class_type='fc_utils')
