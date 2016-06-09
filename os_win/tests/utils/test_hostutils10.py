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

import mock

from os_win import exceptions
from os_win.tests import test_base
from os_win.utils import hostutils10


class HostUtils10TestCase(test_base.OsWinBaseTestCase):
    """Unit tests for the Hyper-V HostUtils10 class."""

    def setUp(self):
        super(HostUtils10TestCase, self).setUp()
        self._hostutils = hostutils10.HostUtils10()
        self._hostutils._conn_hgs_attr = mock.MagicMock()

    @mock.patch.object(hostutils10.HostUtils10, '_get_wmi_conn')
    def test_conn_hgs(self, mock_get_wmi_conn):
        self._hostutils._conn_hgs_attr = None
        self.assertEqual(mock_get_wmi_conn.return_value,
                         self._hostutils._conn_hgs)

        mock_get_wmi_conn.assert_called_once_with(
            self._hostutils._HGS_NAMESPACE % self._hostutils._host)

    @mock.patch.object(hostutils10.HostUtils10, '_get_wmi_conn')
    def test_conn_hgs_no_namespace(self, mock_get_wmi_conn):
        self._hostutils._conn_hgs_attr = None

        mock_get_wmi_conn.side_effect = [exceptions.OSWinException]
        self.assertRaises(exceptions.OSWinException,
                          lambda: self._hostutils._conn_hgs)
        mock_get_wmi_conn.assert_called_once_with(
            self._hostutils._HGS_NAMESPACE % self._hostutils._host)

    def _test_is_host_guarded(self, return_code=0, is_host_guarded=True):
        hgs_config = self._hostutils._conn_hgs.MSFT_HgsClientConfiguration
        hgs_config.Get.return_value = (return_code,
            mock.MagicMock(IsHostGuarded=is_host_guarded))
        expected_result = is_host_guarded and not return_code

        result = self._hostutils.is_host_guarded()
        self.assertEqual(expected_result, result)

    def test_is_guarded_host_config_error(self):
        self._test_is_host_guarded(return_code=mock.sentinel.return_code)

    def test_is_guarded_host(self):
        self._test_is_host_guarded()

    def test_is_not_guarded_host(self):
        self._test_is_host_guarded(is_host_guarded=False)
