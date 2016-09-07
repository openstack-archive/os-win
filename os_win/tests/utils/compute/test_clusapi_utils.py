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

import ddt
import mock

from os_win import constants
from os_win import exceptions
from os_win.tests import test_base
from os_win.utils.compute import _clusapi_utils


@ddt.ddt
class ClusApiUtilsTestCase(test_base.OsWinBaseTestCase):
    def setUp(self):
        super(ClusApiUtilsTestCase, self).setUp()

        self._clusapi = mock.patch.object(
            _clusapi_utils, 'clusapi', create=True).start()

        self._clusapi_utils = _clusapi_utils.ClusApiUtils()

        self._run_patcher = mock.patch.object(self._clusapi_utils,
                                              '_run_and_check_output')
        self._mock_run = self._run_patcher.start()

    def _mock_ctypes(self):
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")
        self._ctypes.c_wchar_p = lambda x: (x, 'c_wchar_p')
        self._ctypes.sizeof = lambda x: (x, 'sizeof')

        mock.patch.object(_clusapi_utils, 'ctypes', self._ctypes).start()

    def test_run_and_check_output(self):
        self._clusapi_utils._win32utils = mock.Mock()
        self._clusapi_utils._run_and_check_output = (
            self._run_patcher.temp_original)

        mock_win32utils_run_and_check_output = (
            self._clusapi_utils._win32utils.run_and_check_output)

        ret_val = self._clusapi_utils._run_and_check_output(
            mock.sentinel.func,
            mock.sentinel.arg,
            fake_kwarg=mock.sentinel.kwarg)

        mock_win32utils_run_and_check_output.assert_called_once_with(
            mock.sentinel.func,
            mock.sentinel.arg,
            fake_kwarg=mock.sentinel.kwarg,
            failure_exc=exceptions.ClusterWin32Exception)
        self.assertEqual(mock_win32utils_run_and_check_output.return_value,
                         ret_val)

    def test_dword_align(self):
        self.assertEqual(8, self._clusapi_utils._dword_align(5))
        self.assertEqual(4, self._clusapi_utils._dword_align(4))

    def test_get_clusprop_value_struct(self):
        val_type = ctypes.c_ubyte * 3
        expected_padding_sz = 1

        clusprop_val_struct = self._clusapi_utils._get_clusprop_value_struct(
            val_type)

        expected_fields = [('syntax', _clusapi_utils.DWORD),
                           ('length', _clusapi_utils.DWORD),
                           ('value', val_type),
                           ('_padding', ctypes.c_ubyte * expected_padding_sz)]
        self.assertEqual(expected_fields, clusprop_val_struct._fields_)

    def test_get_property_list_entry(self):
        fake_prop_name = 'fake prop name'
        fake_prop_syntax = 1
        fake_prop_val = (ctypes.c_wchar * 10)()
        fake_prop_val.value = 'fake prop'

        entry = self._clusapi_utils.get_property_list_entry(
            name=fake_prop_name,
            syntax=fake_prop_syntax,
            value=fake_prop_val)

        self.assertEqual(_clusapi_utils.CLUSPROP_SYNTAX_NAME,
                         entry.name.syntax)
        self.assertEqual(fake_prop_name,
                         entry.name.value)
        self.assertEqual(
            ctypes.sizeof(ctypes.c_wchar) * (len(fake_prop_name) + 1),
            entry.name.length)

        self.assertEqual(fake_prop_syntax,
                         entry.value.syntax)
        self.assertEqual(bytearray(fake_prop_val),
                         bytearray(entry.value.value))
        self.assertEqual(
            ctypes.sizeof(fake_prop_val),
            entry.value.length)

        self.assertEqual(_clusapi_utils.CLUSPROP_SYNTAX_ENDMARK,
                         entry._endmark)

    def test_get_property_list(self):
        entry_0 = self._clusapi_utils.get_property_list_entry(
            name='fake prop name',
            syntax=1,
            value=ctypes.c_uint(2))
        entry_1 = self._clusapi_utils.get_property_list_entry(
            name='fake prop name',
            syntax=2,
            value=ctypes.c_ubyte(5))

        prop_list = self._clusapi_utils.get_property_list(
            [entry_0, entry_1])

        self.assertEqual(2, prop_list.count)
        self.assertEqual(bytearray(entry_0) + bytearray(entry_1),
                         prop_list.entries_buff)

    @ddt.data('fake cluster name', None)
    def test_open_cluster(self, cluster_name):
        self._mock_ctypes()

        handle = self._clusapi_utils.open_cluster(cluster_name)

        expected_handle_arg = (
            self._ctypes.c_wchar_p(cluster_name)
            if cluster_name else None)
        self._mock_run.assert_called_once_with(
            self._clusapi.OpenCluster,
            expected_handle_arg,
            **self._clusapi_utils._open_handle_check_flags)

        self.assertEqual(self._mock_run.return_value, handle)

    def test_open_cluster_group(self):
        self._mock_ctypes()

        handle = self._clusapi_utils.open_cluster_group(
            mock.sentinel.cluster_handle,
            mock.sentinel.group_name)

        self._mock_run.assert_called_once_with(
            self._clusapi.OpenClusterGroup,
            mock.sentinel.cluster_handle,
            self._ctypes.c_wchar_p(mock.sentinel.group_name),
            **self._clusapi_utils._open_handle_check_flags)

        self.assertEqual(self._mock_run.return_value, handle)

    def test_open_cluster_node(self):
        self._mock_ctypes()

        handle = self._clusapi_utils.open_cluster_node(
            mock.sentinel.cluster_handle,
            mock.sentinel.node_name)

        self._mock_run.assert_called_once_with(
            self._clusapi.OpenClusterNode,
            mock.sentinel.cluster_handle,
            self._ctypes.c_wchar_p(mock.sentinel.node_name),
            **self._clusapi_utils._open_handle_check_flags)

        self.assertEqual(self._mock_run.return_value, handle)

    def test_close_cluster(self):
        self._clusapi_utils.close_cluster(mock.sentinel.handle)
        self._clusapi.CloseCluster.assert_called_once_with(
            mock.sentinel.handle)

    def test_close_cluster_group(self):
        self._clusapi_utils.close_cluster_group(mock.sentinel.handle)
        self._clusapi.CloseClusterGroup.assert_called_once_with(
            mock.sentinel.handle)

    def test_close_cluster_node(self):
        self._clusapi_utils.close_cluster_node(mock.sentinel.handle)
        self._clusapi.CloseClusterNode.assert_called_once_with(
            mock.sentinel.handle)

    def test_cancel_cluster_group_operation(self):
        self._clusapi_utils.cancel_cluster_group_operation(
            mock.sentinel.group_handle)

        self._mock_run.assert_called_once_with(
            self._clusapi.CancelClusterGroupOperation,
            mock.sentinel.group_handle,
            0,
            ignored_error_codes=[_clusapi_utils.ERROR_IO_PENDING])

    @ddt.data(mock.sentinel.prop_list, None)
    def test_move_cluster_group(self, prop_list):
        self._mock_ctypes()

        expected_prop_list_arg = (
            self._ctypes.byref(prop_list) if prop_list else None)
        expected_prop_list_sz = (
            self._ctypes.sizeof(prop_list) if prop_list else 0)

        self._clusapi_utils.move_cluster_group(
            mock.sentinel.group_handle,
            mock.sentinel.dest_node_handle,
            mock.sentinel.move_flags,
            prop_list)

        self._mock_run.assert_called_once_with(
            self._clusapi.MoveClusterGroupEx,
            mock.sentinel.group_handle,
            mock.sentinel.dest_node_handle,
            mock.sentinel.move_flags,
            expected_prop_list_arg,
            expected_prop_list_sz,
            ignored_error_codes=[_clusapi_utils.ERROR_IO_PENDING])

    def test_get_cluster_group_state(self):
        owner_node = 'fake owner node'

        def fake_get_state(inst,
                           group_handle, node_name_buff, node_name_len,
                           error_ret_vals, error_on_nonzero_ret_val,
                           ret_val_is_err_code):
            self.assertEqual(mock.sentinel.group_handle, group_handle)

            # Those arguments would not normally get to the ClusApi
            # function, instead being used by the helper invoking
            # it and catching errors. For convenience, we validate
            # those arguments at this point.
            self.assertEqual([constants.CLUSTER_GROUP_STATE_UNKNOWN],
                             error_ret_vals)
            self.assertFalse(error_on_nonzero_ret_val)
            self.assertFalse(ret_val_is_err_code)

            node_name_len_arg = ctypes.cast(
                node_name_len,
                ctypes.POINTER(_clusapi_utils.DWORD)).contents
            self.assertEqual(self._clusapi_utils._MAX_NODE_NAME,
                             node_name_len_arg.value)

            node_name_arg = ctypes.cast(
                node_name_buff,
                ctypes.POINTER(
                    ctypes.c_wchar *
                    self._clusapi_utils._MAX_NODE_NAME)).contents
            node_name_arg.value = owner_node
            return mock.sentinel.group_state

        self._mock_run.side_effect = fake_get_state

        state_info = self._clusapi_utils.get_cluster_group_state(
            mock.sentinel.group_handle)
        expected_state_info = dict(state=mock.sentinel.group_state,
                                   owner_node=owner_node)
        self.assertDictEqual(expected_state_info, state_info)
