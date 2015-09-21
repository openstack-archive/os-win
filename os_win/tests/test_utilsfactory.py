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
from os_win.utils.compute import vmutils
from os_win.utils.compute import vmutilsv2
from os_win.utils import hostutils
from os_win.utils.network import networkutils
from os_win.utils.network import networkutilsv2
from os_win import utilsfactory

CONF = cfg.CONF


class TestHyperVUtilsFactory(base.BaseTestCase):
    def test_get_vmutils_force_v1_and_min_version(self):
        self._test_returned_class(None, True, True)

    def test_get_vmutils_v2(self):
        self._test_returned_class(vmutilsv2.VMUtilsV2, False, True)

    def test_get_vmutils_v2_r2(self):
        self._test_returned_class(vmutils.VMUtils, False, False)

    def test_get_vmutils_force_v1_and_not_min_version(self):
        self._test_returned_class(vmutils.VMUtils, True, False)

    def _test_returned_class(self, expected_class, force_v1, os_supports_v2):
        CONF.set_override('force_hyperv_utils_v1', force_v1, 'hyperv')
        with mock.patch.object(
            hostutils.HostUtils,
            'check_min_windows_version') as mock_check_min_windows_version:
            mock_check_min_windows_version.return_value = os_supports_v2

            if os_supports_v2 and force_v1:
                self.assertRaises(exceptions.HyperVException,
                                  utilsfactory.get_vmutils)
            else:
                actual_class = type(utilsfactory.get_vmutils())
                self.assertEqual(actual_class, expected_class)

    def test_get_networkutils_v2_r2(self):
        self._test_networkutils(expected_class=networkutilsv2.NetworkUtilsV2R2,
                                force_v1=True,
                                os_version='6.3.0')

    def test_get_networkutils_v2(self):
        self._test_networkutils(expected_class=networkutilsv2.NetworkUtilsV2,
                                force_v1=False,
                                os_version='6.2.0')

    def test_get_networkutils_v1_old_version(self):
        self._test_networkutils(expected_class=networkutils.NetworkUtils,
                                force_v1=False,
                                os_version='6.1.0')

    def test_get_networkutils_v1_forced(self):
        self._test_networkutils(expected_class=networkutils.NetworkUtils,
                                force_v1=True,
                                os_version='6.2.0')

    @mock.patch.object(utilsfactory.utils, 'get_windows_version')
    def _test_networkutils(self, mock_get_win_version, expected_class,
                           force_v1, os_version):
        CONF.set_override('force_hyperv_utils_v1', force_v1, 'hyperv')
        mock_get_win_version.return_value = os_version

        actual_class = type(utilsfactory.get_networkutils())
        self.assertEqual(actual_class, expected_class)
