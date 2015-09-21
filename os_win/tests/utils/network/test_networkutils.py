#  Copyright 2014 Cloudbase Solutions Srl
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
from os_win.utils import constants
from os_win.utils.network import networkutils


class NetworkUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V NetworkUtils class."""

    _FAKE_PORT = {'Name': mock.sentinel.FAKE_PORT_NAME}
    _FAKE_RET_VALUE = 0
    FAKE_VLAN_ID = 500

    _MSVM_VIRTUAL_SWITCH = 'Msvm_VirtualSwitch'

    def setUp(self):
        self.netutils = networkutils.NetworkUtils()
        self.netutils._conn = mock.MagicMock()

        super(NetworkUtilsTestCase, self).setUp()

    def test_get_external_vswitch(self):
        mock_vswitch = mock.MagicMock()
        mock_vswitch.path_.return_value = mock.sentinel.FAKE_VSWITCH_PATH
        getattr(self.netutils._conn,
                self._MSVM_VIRTUAL_SWITCH).return_value = [mock_vswitch]

        switch_path = self.netutils.get_external_vswitch(
            mock.sentinel.FAKE_VSWITCH_NAME)

        self.assertEqual(mock.sentinel.FAKE_VSWITCH_PATH, switch_path)

    def test_get_external_vswitch_not_found(self):
        self.netutils._conn.Msvm_VirtualEthernetSwitch.return_value = []

        self.assertRaises(exceptions.HyperVException,
                          self.netutils.get_external_vswitch,
                          mock.sentinel.FAKE_VSWITCH_NAME)

    def test_get_external_vswitch_no_name(self):
        mock_vswitch = mock.MagicMock()
        mock_vswitch.path_.return_value = mock.sentinel.FAKE_VSWITCH_PATH

        mock_ext_port = self.netutils._conn.Msvm_ExternalEthernetPort()[0]
        self._prepare_external_port(mock_vswitch, mock_ext_port)

        switch_path = self.netutils.get_external_vswitch(None)
        self.assertEqual(mock.sentinel.FAKE_VSWITCH_PATH, switch_path)

    def _prepare_external_port(self, mock_vswitch, mock_ext_port):
        mock_lep = mock_ext_port.associators()[0]
        mock_lep.associators.return_value = [mock_vswitch]

    def test_get_vswitch_external_port(self):
        ext_port = mock.MagicMock()
        self.netutils._conn.Msvm_ExternalEthernetPort.return_value = [ext_port]
        lan_endpoint = mock.MagicMock()
        ext_port.associators.return_value = [lan_endpoint]
        vswitch_port = mock.MagicMock()
        lan_endpoint.associators.return_value = [vswitch_port]
        vswitch = mock.MagicMock()
        vswitch.ElementName = mock.sentinel.FAKE_VSWITCH_NAME
        vswitch_port.associators.return_value = [vswitch]

        result = self.netutils._get_vswitch_external_port(
            mock.sentinel.FAKE_VSWITCH_NAME)

        self.assertEqual(vswitch_port, result)

        ext_port.associators.assert_called_once_with(
            wmi_result_class=self.netutils._SWITCH_LAN_ENDPOINT)
        lan_endpoint.associators.assert_called_once_with(
            wmi_result_class=self.netutils._ETHERNET_SWITCH_PORT)
        vswitch_port.associators.assert_called_once_with(
            wmi_result_class=self.netutils._VIRTUAL_SWITCH)

    @mock.patch.object(networkutils.NetworkUtils, "_get_vswitch_external_port")
    def _check_set_switch_ext_port_trunk_vlan(
            self, mock_get_vswitch_external_port, desired_endpoint_mode,
            trunked_list):
        vswitch_external_port = mock_get_vswitch_external_port.return_value
        vlan_endpoint = mock.MagicMock()
        vlan_endpoint.SupportedEndpointModes = [constants.TRUNK_ENDPOINT_MODE]
        vlan_endpoint.DesiredEndpointMode = mock.sentinel.endpoint_mode
        if desired_endpoint_mode is not constants.TRUNK_ENDPOINT_MODE:
            vlan_endpoint.put.side_effect = Exception
        vswitch_external_port.associators.return_value = [vlan_endpoint]
        vlan_endpoint_settings = mock.MagicMock()
        vlan_endpoint_settings.TrunkedVLANList = trunked_list
        vlan_endpoint.associators.return_value = [vlan_endpoint_settings]

        self.netutils.set_switch_external_port_trunk_vlan(
            mock.sentinel.FAKE_VSWITCH_NAME, self.FAKE_VLAN_ID,
            desired_endpoint_mode)

        mock_get_vswitch_external_port.assert_called_once_with(
            mock.sentinel.FAKE_VSWITCH_NAME)
        vswitch_external_port.associators.assert_called_once_with(
            wmi_association_class=self.netutils._BINDS_TO)
        vlan_endpoint.associators.assert_called_once_with(
            wmi_result_class=self.netutils._VLAN_ENDPOINT_SET_DATA)

        self.assertIn(self.FAKE_VLAN_ID,
                      vlan_endpoint_settings.TrunkedVLANList)

        if desired_endpoint_mode is constants.TRUNK_ENDPOINT_MODE:
            self.assertEqual(desired_endpoint_mode,
                             vlan_endpoint.DesiredEndpointMode)
        else:
            self.assertEqual(mock.sentinel.endpoint_mode,
                             vlan_endpoint.DesiredEndpointMode)

    @mock.patch.object(networkutils.NetworkUtils, "_get_vswitch_external_port")
    def test_set_switch_ext_port_trunk_vlan_internal(
            self, mock_get_vswitch_external_port):
        mock_get_vswitch_external_port.return_value = None

        self.netutils.set_switch_external_port_trunk_vlan(
            mock.sentinel.FAKE_VSWITCH_NAME, self.FAKE_VLAN_ID,
            constants.TRUNK_ENDPOINT_MODE)

        mock_get_vswitch_external_port.assert_called_once_with(
            mock.sentinel.FAKE_VSWITCH_NAME)

    def test_set_switch_ext_port_trunk_vlan_trunked_missing(self):
        self._check_set_switch_ext_port_trunk_vlan(
            desired_endpoint_mode=constants.TRUNK_ENDPOINT_MODE,
            trunked_list=[])

    def test_set_switch_ext_port_trunk_vlan_trunked_added(self):
        self._check_set_switch_ext_port_trunk_vlan(
            desired_endpoint_mode=constants.TRUNK_ENDPOINT_MODE,
            trunked_list=[self.FAKE_VLAN_ID])

    def test_set_switch_ext_port_trunk_vlan_unsupported_endpoint_mode(self):
        self._check_set_switch_ext_port_trunk_vlan(
            desired_endpoint_mode=mock.sentinel.unsupported_endpoint_mode,
            trunked_list=[])

    def test_create_vswitch_port(self):
        svc = self.netutils._conn.Msvm_VirtualSwitchManagementService()[0]
        svc.CreateSwitchPort.return_value = (
            self._FAKE_PORT, self._FAKE_RET_VALUE)

        port = self.netutils.create_vswitch_port(
            mock.sentinel.FAKE_VSWITCH_PATH, mock.sentinel.FAKE_PORT_NAME)

        svc.CreateSwitchPort.assert_called_once_with(
            Name=mock.ANY, FriendlyName=mock.sentinel.FAKE_PORT_NAME,
            ScopeOfResidence="", VirtualSwitch=mock.sentinel.FAKE_VSWITCH_PATH)
        self.assertEqual(self._FAKE_PORT, port)

    def test_vswitch_port_needed(self):
        self.assertTrue(self.netutils.vswitch_port_needed())

    @mock.patch.object(networkutils.NetworkUtils,
                       "_get_switch_port_path_by_name")
    def test_disconnect_switch_port_not_found(self, mock_get_swp_path):
        mock_svc = self.netutils._conn.Msvm_VirtualSwitchManagementService()[0]
        mock_get_swp_path.return_value = None

        self.netutils.disconnect_switch_port(mock.sentinel.FAKE_PORT_NAME,
                                             True, True)
        self.assertFalse(mock_svc.DisconnectSwitchPort.called)
        self.assertFalse(mock_svc.DeleteSwitchPort.called)

    @mock.patch.object(networkutils.NetworkUtils,
                       "_get_switch_port_path_by_name")
    def test_disconnect_switch_port(self, mock_get_swp_path):
        mock_svc = self.netutils._conn.Msvm_VirtualSwitchManagementService()[0]
        mock_svc.DisconnectSwitchPort.return_value = (0, )
        mock_svc.DeleteSwitchPort.return_value = (0, )
        mock_get_swp_path.return_value = mock.sentinel.FAKE_PATH

        self.netutils.disconnect_switch_port(mock.sentinel.FAKE_PORT_NAME,
                                             False, True)
        mock_svc.DisconnectSwitchPort.assert_called_once_with(
            SwitchPort=mock.sentinel.FAKE_PATH)
        mock_svc.DeleteSwitchPort.assert_called_once_with(
            SwitchPort=mock.sentinel.FAKE_PATH)

    @mock.patch.object(networkutils.NetworkUtils,
                       "_get_switch_port_path_by_name")
    def test_disconnect_switch_port_disconnected(self, mock_get_swp_path):
        mock_svc = self.netutils._conn.Msvm_VirtualSwitchManagementService()[0]
        mock_svc.DeleteSwitchPort.return_value = (0, )
        mock_get_swp_path.return_value = mock.sentinel.FAKE_PATH

        self.netutils.disconnect_switch_port(mock.sentinel.FAKE_PORT_NAME,
                                             True, True)

        self.assertFalse(mock_svc.DisconnectSwitchPort.called)
        mock_svc.DeleteSwitchPort.assert_called_once_with(
            SwitchPort=mock.sentinel.FAKE_PATH)

    @mock.patch.object(networkutils.NetworkUtils,
                       "_get_switch_port_path_by_name")
    def test_disconnect_switch_port_disconnect_ex(self, mock_get_swp_path):
        mock_svc = self.netutils._conn.Msvm_VirtualSwitchManagementService()[0]
        mock_svc.DisconnectSwitchPort.return_value = (
            mock.sentinel.FAKE_VAL, )
        mock_get_swp_path.return_value = mock.sentinel.FAKE_PATH

        self.assertRaises(exceptions.HyperVException,
                          self.netutils.disconnect_switch_port,
                          mock.sentinel.FAKE_PORT_NAME,
                          False, True)

        mock_svc.DisconnectSwitchPort.assert_called_once_with(
            SwitchPort=mock.sentinel.FAKE_PATH)

    @mock.patch.object(networkutils.NetworkUtils,
                       "_get_switch_port_path_by_name")
    def test_disconnect_switch_port_delete_ex(self, mock_get_swp_path):
        mock_svc = self.netutils._conn.Msvm_VirtualSwitchManagementService()[0]
        mock_svc.DeleteSwitchPort.return_value = (mock.sentinel.FAKE_VAL, )
        mock_get_swp_path.return_value = mock.sentinel.FAKE_PATH

        self.assertRaises(exceptions.HyperVException,
                          self.netutils.disconnect_switch_port,
                          mock.sentinel.FAKE_PORT_NAME,
                          True, True)

        mock_svc.DeleteSwitchPort.assert_called_once_with(
            SwitchPort=mock.sentinel.FAKE_PATH)
