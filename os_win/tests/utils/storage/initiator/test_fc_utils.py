# Copyright 2015 Cloudbase Solutions Srl
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
import mock
from oslotest import base
import six

from os_win import exceptions
from os_win.utils.storage.initiator import fc_structures as fc_struct
from os_win.utils.storage.initiator import fc_utils


class FCUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V FCUtils class."""

    _FAKE_ADAPTER_NAME = 'fake_adapter_name'
    _FAKE_ADAPTER_WWN = list(range(8))

    def setUp(self):
        super(FCUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        self._fc_utils = fc_utils.FCUtils()
        self._run_mocker = mock.patch.object(self._fc_utils,
                                             '_run_and_check_output')
        self._run_mocker.start()

        self._mock_run = self._fc_utils._run_and_check_output

        self.addCleanup(mock.patch.stopall)

    def _setup_lib_mocks(self):
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")

        mock.patch.object(fc_utils, 'hbaapi', create=True).start()
        self._ctypes_mocker = mock.patch.object(fc_utils, 'ctypes',
                                                self._ctypes)
        self._ctypes_mocker.start()

    def test_run_and_check_output(self):
        self._run_mocker.stop()
        with mock.patch.object(fc_utils.win32utils.Win32Utils,
                               'run_and_check_output') as mock_win32_run:
            self._fc_utils._run_and_check_output(
                adapter_name=self._FAKE_ADAPTER_NAME)

            mock_win32_run.assert_called_once_with(
                adapter_name=self._FAKE_ADAPTER_NAME,
                failure_exc=exceptions.FCWin32Exception)

    def test_get_fc_hba_count(self):
        hba_count = self._fc_utils.get_fc_hba_count()

        fc_utils.hbaapi.HBA_GetNumberOfAdapters.assert_called_once_with()
        self.assertEqual(fc_utils.hbaapi.HBA_GetNumberOfAdapters.return_value,
                         hba_count)

    def _test_open_adapter(self, adapter_name=None, adapter_wwn=None):
        self._ctypes_mocker.stop()
        self._mock_run.return_value = mock.sentinel.handle

        if adapter_name:
            expected_func = fc_utils.hbaapi.HBA_OpenAdapter
        elif adapter_wwn:
            expected_func = fc_utils.hbaapi.HBA_OpenAdapterByWWN

        resulted_handle = self._fc_utils._open_adapter(
            adapter_name=adapter_name, adapter_wwn=adapter_wwn)

        args_list = self._mock_run.call_args_list[0][0]
        self.assertEqual(expected_func, args_list[0])
        if adapter_name:
            self.assertEqual(six.b(adapter_name),
                             args_list[1].value)
        else:
            self.assertEqual(adapter_wwn, list(args_list[1]))

        self.assertEqual(mock.sentinel.handle, resulted_handle)

    def test_open_adapter_by_name(self):
        self._test_open_adapter(adapter_name=self._FAKE_ADAPTER_NAME)

    def test_open_adapter_by_wwn(self):
        self._test_open_adapter(adapter_wwn=self._FAKE_ADAPTER_WWN)

    def test_open_adapter_not_specified(self):
        self.assertRaises(exceptions.FCException,
                          self._fc_utils._open_adapter)

    def test_close_adapter(self):
        self._fc_utils._close_adapter(mock.sentinel.hba_handle)
        fc_utils.hbaapi.HBA_CloseAdapter.assert_called_once_with(
            mock.sentinel.hba_handle)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    def test_get_hba_handle(self, mock_close_adapter, mock_open_adapter):
        with self._fc_utils._get_hba_handle(
                adapter_name=self._FAKE_ADAPTER_NAME):
            mock_open_adapter.assert_called_once_with(
                adapter_name=self._FAKE_ADAPTER_NAME)
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter.return_value)

    @mock.patch.object(ctypes, 'byref')
    def test_get_adapter_name(self, mock_byref):
        self._ctypes_mocker.stop()
        fake_adapter_index = 1

        def update_buff(buff):
            buff.value = six.b(self._FAKE_ADAPTER_NAME)

        mock_byref.side_effect = update_buff

        resulted_adapter_name = self._fc_utils._get_adapter_name(
            fake_adapter_index)

        args_list = self._mock_run.call_args_list[0][0]

        self.assertEqual(fc_utils.hbaapi.HBA_GetAdapterName,
                         args_list[0])
        self.assertIsInstance(args_list[1], ctypes.c_uint32)
        self.assertEqual(fake_adapter_index, args_list[1].value)

        arg_byref = mock_byref.call_args_list[0][0][0]
        buff = ctypes.cast(arg_byref, ctypes.POINTER(
            ctypes.c_char * 256)).contents
        self.assertIsInstance(buff, ctypes.c_char * 256)
        self.assertEqual(self._FAKE_ADAPTER_NAME, resulted_adapter_name)

    @mock.patch.object(fc_struct, 'get_target_mapping_struct')
    def test_get_target_mapping(self, mock_get_target_mapping):
        fake_entry_count = 10
        hresults = [fc_utils.HBA_STATUS_ERROR_MORE_DATA,
                    fc_utils.HBA_STATUS_OK]
        mock_mapping = mock.Mock(NumberOfEntries=fake_entry_count)
        mock_get_target_mapping.return_value = mock_mapping
        self._mock_run.side_effect = hresults

        resulted_mapping = self._fc_utils._get_target_mapping(
            mock.sentinel.hba_handle)

        expected_calls = [
            mock.call(fc_utils.hbaapi.HBA_GetFcpTargetMapping,
                      mock.sentinel.hba_handle,
                      self._ctypes.byref(mock_mapping),
                      ignored_error_codes=[fc_utils.HBA_STATUS_ERROR_MORE_DATA]
                      )] * 2
        self._mock_run.assert_has_calls(expected_calls)
        self.assertEqual(mock_mapping, resulted_mapping)
        mock_get_target_mapping.assert_has_calls([mock.call(0),
                                                  mock.call(fake_entry_count)])

    @mock.patch.object(fc_struct, 'HBA_PortAttributes')
    def test_get_adapter_port_attributes(self, mock_class_HBA_PortAttributes):
        resulted_port_attributes = self._fc_utils._get_adapter_port_attributes(
            mock.sentinel.hba_handle, mock.sentinel.port_index)

        self._mock_run.assert_called_once_with(
            fc_utils.hbaapi.HBA_GetAdapterPortAttributes,
            mock.sentinel.hba_handle,
            mock.sentinel.port_index,
            self._ctypes.byref(mock_class_HBA_PortAttributes.return_value))

        self.assertEqual(mock_class_HBA_PortAttributes.return_value,
                         resulted_port_attributes)

    @mock.patch.object(fc_struct, 'HBA_AdapterAttributes')
    def test_get_adapter_attributes(self, mock_class_HBA_AdapterAttributes):
        resulted_hba_attributes = self._fc_utils._get_adapter_attributes(
            mock.sentinel.hba_handle)

        self._mock_run.assert_called_once_with(
            fc_utils.hbaapi.HBA_GetAdapterAttributes,
            mock.sentinel.hba_handle,
            self._ctypes.byref(mock_class_HBA_AdapterAttributes.return_value))

        self.assertEqual(mock_class_HBA_AdapterAttributes.return_value,
                         resulted_hba_attributes)

    @mock.patch.object(fc_utils.FCUtils, 'get_fc_hba_count')
    def test_get_fc_hba_ports_missing_hbas(self, mock_get_fc_hba_count):
        mock_get_fc_hba_count.return_value = 0

        resulted_hba_ports = self._fc_utils.get_fc_hba_ports()

        self.assertEqual([], resulted_hba_ports)

    @mock.patch.object(fc_utils.FCUtils, '_get_fc_hba_adapter_ports')
    @mock.patch.object(fc_utils.FCUtils, '_get_adapter_name')
    @mock.patch.object(fc_utils.FCUtils, 'get_fc_hba_count')
    def test_get_fc_hba_ports(self, mock_get_fc_hba_count,
                              mock_get_adapter_name,
                              mock_get_adapter_ports):
        fake_adapter_count = 2

        mock_get_adapter_name.return_value = mock.sentinel.adapter_name
        mock_get_fc_hba_count.return_value = fake_adapter_count
        mock_get_adapter_ports.side_effect = [Exception,
                                              [mock.sentinel.port]]

        expected_hba_ports = [mock.sentinel.port]
        resulted_hba_ports = self._fc_utils.get_fc_hba_ports()
        self.assertEqual(expected_hba_ports, resulted_hba_ports)
        self.assertEqual(expected_hba_ports, resulted_hba_ports)

        mock_get_adapter_name.assert_has_calls(
            [mock.call(index) for index in range(fake_adapter_count)])
        mock_get_adapter_ports.assert_has_calls(
            [mock.call(mock.sentinel.adapter_name)] * fake_adapter_count)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_get_adapter_port_attributes')
    @mock.patch.object(fc_utils.FCUtils, '_get_adapter_attributes')
    def test_get_fc_hba_adapter_ports(self, mock_get_adapter_attributes,
                                      mock_get_adapter_port_attributes,
                                      mock_close_adapter,
                                      mock_open_adapter):
        fake_port_count = 1
        fake_port_index = 0
        # Local WWNs
        fake_node_wwn = list(range(3))
        fake_port_wwn = list(range(3))

        mock_adapter_attributes = mock.MagicMock()
        mock_adapter_attributes.NumberOfPorts = fake_port_count
        mock_port_attributes = mock.MagicMock()
        mock_port_attributes.NodeWWN = fake_node_wwn
        mock_port_attributes.PortWWN = fake_port_wwn

        mock_get_adapter_attributes.return_value = mock_adapter_attributes
        mock_get_adapter_port_attributes.return_value = mock_port_attributes

        resulted_hba_ports = self._fc_utils._get_fc_hba_adapter_ports(
            mock.sentinel.adapter_name)

        expected_hba_ports = [{
            'node_name': self._fc_utils._wwn_array_to_hex_str(fake_node_wwn),
            'port_name': self._fc_utils._wwn_array_to_hex_str(fake_port_wwn)
        }]
        self.assertEqual(expected_hba_ports, resulted_hba_ports)

        mock_open_adapter.assert_called_once_with(
            adapter_name=mock.sentinel.adapter_name)
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter(mock.sentinel.adapter_nam))
        mock_get_adapter_attributes.assert_called_once_with(
            mock_open_adapter.return_value)
        mock_get_adapter_port_attributes.assert_called_once_with(
            mock_open_adapter.return_value, fake_port_index)

    def test_wwn_hex_string_to_array(self):
        fake_wwn_hex_string = '000102'

        resulted_array = self._fc_utils._wwn_hex_string_to_array(
            fake_wwn_hex_string)

        expected_wwn_hex_array = list(range(3))
        self.assertEqual(expected_wwn_hex_array, resulted_array)

    def test_wwn_array_to_hex_str(self):
        fake_wwn_array = list(range(3))

        resulted_string = self._fc_utils._wwn_array_to_hex_str(fake_wwn_array)

        expected_string = '000102'
        self.assertEqual(expected_string, resulted_string)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_get_target_mapping')
    def test_get_fc_target_mapping(self, mock_get_target_mapping,
                                   mock_close_adapter, mock_open_adapter):
        # Local WWNN
        fake_node_wwn_string = "123"
        # Remote WWNs
        fake_node_wwn = list(range(3))
        fake_port_wwn = list(range(3))

        mock_fcp_mappings = mock.MagicMock()
        mock_entry = mock.MagicMock()
        mock_entry.FcpId.NodeWWN = fake_node_wwn
        mock_entry.FcpId.PortWWN = fake_port_wwn
        mock_entry.ScsiId.OSDeviceName = mock.sentinel.OSDeviceName
        mock_entry.ScsiId.ScsiOSLun = mock.sentinel.ScsiOSLun
        mock_fcp_mappings.Entries = [mock_entry]
        mock_get_target_mapping.return_value = mock_fcp_mappings
        mock_node_wwn = self._fc_utils._wwn_hex_string_to_array(
            fake_node_wwn_string)

        resulted_mappings = self._fc_utils.get_fc_target_mappings(
            fake_node_wwn_string)

        expected_mappings = [{
            'node_name': self._fc_utils._wwn_array_to_hex_str(fake_node_wwn),
            'port_name': self._fc_utils._wwn_array_to_hex_str(fake_port_wwn),
            'device_name': mock.sentinel.OSDeviceName,
            'lun': mock.sentinel.ScsiOSLun
        }]
        self.assertEqual(expected_mappings, resulted_mappings)
        mock_open_adapter.assert_called_once_with(adapter_wwn=mock_node_wwn)
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter.return_value)

    def test_refresh_hba_configuration(self):
        self._fc_utils.refresh_hba_configuration()

        expected_func = fc_utils.hbaapi.HBA_RefreshAdapterConfiguration
        expected_func.assert_called_once_with()
