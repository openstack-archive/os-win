#  Copyright 2013 Cloudbase Solutions Srl
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

import os

import mock
from oslotest import base

from os_win import exceptions
from os_win.utils import constants
from os_win.utils.storage.virtdisk import (
    virtdisk_constants as vdisk_const)
from os_win.utils.storage.virtdisk import vhdutils


class VHDUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V VHDUtils class."""

    def setUp(self):
        super(VHDUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        self._fake_vst_struct = self._vdisk_struct.Win32_VIRTUAL_STORAGE_TYPE

        self._vhdutils = vhdutils.VHDUtils()
        self._vhdutils._win32_utils = mock.Mock()

        self._mock_run = self._vhdutils._win32_utils.run_and_check_output
        self._run_args = self._vhdutils._virtdisk_run_args

        self.addCleanup(mock.patch.stopall)

    def _setup_lib_mocks(self):
        self._vdisk_struct = mock.Mock()
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")
        self._ctypes.c_wchar_p = lambda x: (x, "c_wchar_p")
        self._ctypes.c_ulong = lambda x: (x, "c_ulong")

        mock.patch.multiple(vhdutils,
                            ctypes=self._ctypes, kernel32=mock.DEFAULT,
                            wintypes=mock.DEFAULT, virtdisk=mock.DEFAULT,
                            vdisk_struct=self._vdisk_struct,
                            create=True).start()

    @mock.patch.object(vhdutils.VHDUtils, '_close')
    def _test_run_and_check_output(self, mock_close, raised_exc=None):
        self._mock_run.side_effect = raised_exc(
            func_name='fake_func_name',
            error_code='fake_error_code',
            error_message='fake_error_message') if raised_exc else None

        if raised_exc:
            self.assertRaises(
                raised_exc,
                self._vhdutils._run_and_check_output,
                mock.sentinel.func,
                mock.sentinel.arg,
                cleanup_handle=mock.sentinel.handle)
        else:
            ret_val = self._vhdutils._run_and_check_output(
                mock.sentinel.func,
                mock.sentinel.arg,
                cleanup_handle=mock.sentinel.handle)
            self.assertEqual(self._mock_run.return_value, ret_val)

        self._mock_run.assert_called_once_with(
            mock.sentinel.func, mock.sentinel.arg, **self._run_args)
        mock_close.assert_called_once_with(mock.sentinel.handle)

    def test_run_and_check_output(self):
        self._test_run_and_check_output()

    def test_run_and_check_output_raising_error(self):
        self._test_run_and_check_output(
            raised_exc=exceptions.VHDWin32APIException)

    @mock.patch.object(vhdutils.VHDUtils, '_get_vhd_device_id')
    def test_open(self, mock_get_dev_id):
        fake_vst = self._fake_vst_struct.return_value

        mock_get_dev_id.return_value = mock.sentinel.device_id

        handle = self._vhdutils._open(
            vhd_path=mock.sentinel.vhd_path,
            open_flag=mock.sentinel.open_flag,
            open_access_mask=mock.sentinel.access_mask,
            open_params=mock.sentinel.open_params)

        self.assertEqual(vhdutils.wintypes.HANDLE.return_value, handle)
        self._fake_vst_struct.assert_called_once_with(
            DeviceId=mock.sentinel.device_id)

        self._mock_run.assert_called_once_with(
            vhdutils.virtdisk.OpenVirtualDisk,
            self._ctypes.byref(fake_vst),
            self._ctypes.c_wchar_p(mock.sentinel.vhd_path),
            mock.sentinel.access_mask,
            mock.sentinel.open_flag,
            mock.sentinel.open_params,
            self._ctypes.byref(vhdutils.wintypes.HANDLE.return_value),
            **self._run_args)

    def test_close(self):
        self._vhdutils._close(mock.sentinel.handle)
        vhdutils.kernel32.CloseHandle.assert_called_once_with(
            mock.sentinel.handle)

    @mock.patch.object(vhdutils.VHDUtils, '_get_vhd_device_id')
    @mock.patch.object(vhdutils.VHDUtils, '_close')
    def _test_create_vhd(self, mock_close, mock_get_dev_id, new_vhd_type):
        create_params_struct = (
            self._vdisk_struct.Win32_CREATE_VIRTUAL_DISK_PARAMETERS)
        mock_handle = vhdutils.wintypes.HANDLE.return_value

        expected_create_vhd_flag = (
            vdisk_const.CREATE_VIRTUAL_DISK_FLAGS.get(new_vhd_type))

        self._vhdutils.create_vhd(
            new_vhd_path=mock.sentinel.new_vhd_path,
            new_vhd_type=new_vhd_type,
            src_path=mock.sentinel.src_path,
            max_internal_size=mock.sentinel.max_internal_size,
            parent_path=mock.sentinel.parent_path)

        self._fake_vst_struct.assert_called_once_with(
            DeviceId=mock_get_dev_id.return_value)
        create_params_struct.assert_called_once_with(
            MaximumSize=mock.sentinel.max_internal_size,
            ParentPath=mock.sentinel.parent_path,
            SourcePath=mock.sentinel.src_path)

        self._mock_run.assert_called_once_with(
            vhdutils.virtdisk.CreateVirtualDisk,
            self._ctypes.byref(self._fake_vst_struct.return_value),
            self._ctypes.c_wchar_p(mock.sentinel.new_vhd_path), None,
            None, expected_create_vhd_flag, None,
            self._ctypes.byref(create_params_struct.return_value), None,
            self._ctypes.byref(mock_handle),
            **self._run_args)

        mock_close.assert_called_once_with(mock_handle)

    def test_create_dynamic_vhd(self):
        self._test_create_vhd(new_vhd_type=constants.VHD_TYPE_DYNAMIC)

    def test_create_fixed_vhd(self):
        self._test_create_vhd(new_vhd_type=constants.VHD_TYPE_FIXED)

    @mock.patch.object(vhdutils.VHDUtils, 'create_vhd')
    def test_create_dynamic_vhd_helper(self, mock_create_vhd):
        self._vhdutils.create_dynamic_vhd(mock.sentinel.path,
                                          mock.sentinel.size)

        mock_create_vhd.assert_called_once_with(
            mock.sentinel.path,
            constants.VHD_TYPE_DYNAMIC,
            max_internal_size=mock.sentinel.size)

    @mock.patch.object(vhdutils.VHDUtils, 'create_vhd')
    def test_create_differencing_vhd_helper(self, mock_create_vhd):
        self._vhdutils.create_differencing_vhd(mock.sentinel.path,
                                               mock.sentinel.parent_path)

        mock_create_vhd.assert_called_once_with(
            mock.sentinel.path,
            constants.VHD_TYPE_DIFFERENCING,
            parent_path=mock.sentinel.parent_path)

    @mock.patch.object(vhdutils.VHDUtils, 'create_vhd')
    def test_convert_vhd(self, mock_create_vhd):
        self._vhdutils.convert_vhd(mock.sentinel.src,
                                   mock.sentinel.dest,
                                   mock.sentinel.vhd_type)

        mock_create_vhd.assert_called_once_with(
            mock.sentinel.dest,
            mock.sentinel.vhd_type,
            src_path=mock.sentinel.src)

    def test_get_vhd_format_found_by_ext(self):
        fake_vhd_path = 'C:\\test.vhd'

        ret_val = self._vhdutils.get_vhd_format(fake_vhd_path)

        self.assertEqual(constants.DISK_FORMAT_VHD, ret_val)

    @mock.patch.object(vhdutils.VHDUtils, '_get_vhd_format_by_signature')
    @mock.patch('os.path.exists')
    def _test_vhd_format_unrecognized_ext(self, mock_exists,
                                          mock_get_vhd_fmt_by_sign,
                                          signature_available=False):
        mock_exists.return_value = True
        fake_vhd_path = 'C:\\test_vhd'
        mock_get_vhd_fmt_by_sign.return_value = (
            constants.DISK_FORMAT_VHD if signature_available else None)

        if signature_available:
            ret_val = self._vhdutils.get_vhd_format(fake_vhd_path)
            self.assertEqual(constants.DISK_FORMAT_VHD, ret_val)
        else:
            self.assertRaises(exceptions.VHDException,
                              self._vhdutils.get_vhd_format,
                              fake_vhd_path)

    def test_get_vhd_format_unrecognised_ext_unavailable_signature(self):
        self._test_vhd_format_unrecognized_ext()

    def test_get_vhd_format_unrecognised_ext_available_signature(self):
        self._test_vhd_format_unrecognized_ext(signature_available=True)

    @mock.patch.object(vhdutils.VHDUtils, 'get_vhd_format')
    def test_get_vhd_device_id(self, mock_get_vhd_fmt):
        mock_get_vhd_fmt.return_value = constants.DISK_FORMAT_VHD

        dev_id = self._vhdutils._get_vhd_device_id(mock.sentinel.vhd_path)

        mock_get_vhd_fmt.assert_called_once_with(mock.sentinel.vhd_path)
        self.assertEqual(vdisk_const.VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
                         dev_id)

    def _mock_open(self, read_data=None, curr_f_pos=0):
        mock_open = mock.mock_open()
        mock.patch.object(vhdutils, 'open', mock_open,
                          create=True).start()

        f = mock_open.return_value
        f.read.side_effect = read_data
        f.tell.return_value = curr_f_pos

        return mock_open

    def test_get_vhd_format_by_sig_vhdx(self):
        read_data = (vdisk_const.VHDX_SIGNATURE, )
        self._mock_open(read_data=read_data)

        fmt = self._vhdutils._get_vhd_format_by_signature(
            mock.sentinel.vhd_path)

        self.assertEqual(constants.DISK_FORMAT_VHDX, fmt)

    def test_get_vhd_format_by_sig_vhd(self):
        read_data = ('notthesig', vdisk_const.VHD_SIGNATURE)
        mock_open = self._mock_open(read_data=read_data, curr_f_pos=1024)

        fmt = self._vhdutils._get_vhd_format_by_signature(
            mock.sentinel.vhd_path)

        self.assertEqual(constants.DISK_FORMAT_VHD, fmt)
        mock_open.return_value.seek.assert_has_calls([mock.call(0, 2),
                                                      mock.call(-512, 2)])

    def test_get_vhd_format_by_sig_invalid_format(self):
        self._mock_open(read_data='notthesig', curr_f_pos=1024)

        fmt = self._vhdutils._get_vhd_format_by_signature(
            mock.sentinel.vhd_path)

        self.assertIsNone(fmt)

    def test_get_vhd_format_by_sig_zero_length_file(self):
        mock_open = self._mock_open(read_data=('', ''))

        fmt = self._vhdutils._get_vhd_format_by_signature(
            mock.sentinel.vhd_path)

        self.assertIsNone(fmt)
        mock_open.return_value.seek.assert_called_once_with(0, 2)

    @mock.patch.object(vhdutils.VHDUtils, '_open')
    @mock.patch.object(vhdutils.VHDUtils, '_close')
    @mock.patch.object(vhdutils.VHDUtils, '_get_vhd_info_member')
    def test_get_vhd_info(self, mock_get_vhd_info_member,
                          mock_close, mock_open):
        fake_info_member = vdisk_const.GET_VIRTUAL_DISK_INFO_SIZE
        fake_vhd_info = {'VirtualSize': mock.sentinel.virtual_size}

        mock_open.return_value = mock.sentinel.handle
        mock_get_vhd_info_member.return_value = fake_vhd_info

        ret_val = self._vhdutils.get_vhd_info(mock.sentinel.vhd_path,
                                              [fake_info_member])

        self.assertEqual(fake_vhd_info, ret_val)
        mock_open.assert_called_once_with(
            mock.sentinel.vhd_path,
            open_access_mask=vdisk_const.VIRTUAL_DISK_ACCESS_GET_INFO)
        self._vhdutils._get_vhd_info_member.assert_called_once_with(
            mock.sentinel.handle,
            fake_info_member)
        mock_close.assert_called_once_with(mock.sentinel.handle)

    @mock.patch.object(vhdutils.VHDUtils, '_parse_vhd_info')
    def test_get_vhd_info_member(self, mock_parse_vhd_info):
        get_vd_info_struct = (
            self._vdisk_struct.Win32_GET_VIRTUAL_DISK_INFO_PARAMETERS)
        fake_params = get_vd_info_struct.return_value
        fake_info_size = self._ctypes.sizeof.return_value

        info_member = vdisk_const.GET_VIRTUAL_DISK_INFO_PARENT_LOCATION

        vhd_info = self._vhdutils._get_vhd_info_member(
            mock.sentinel.vhd_path,
            info_member)

        self._mock_run.assert_called_once_with(
            vhdutils.virtdisk.GetVirtualDiskInformation,
            mock.sentinel.vhd_path,
            self._ctypes.byref(
                self._ctypes.c_ulong(fake_info_size)),
            self._ctypes.byref(fake_params), None,
            ignored_error_codes=[vdisk_const.ERROR_VHD_INVALID_TYPE],
            **self._run_args)

        self.assertEqual(mock_parse_vhd_info.return_value, vhd_info)
        mock_parse_vhd_info.assert_called_once_with(fake_params,
                                                    info_member)

    def test_parse_vhd_info(self):
        fake_info_member = vdisk_const.GET_VIRTUAL_DISK_INFO_SIZE
        fake_info = mock.Mock()
        fake_info.VhdInfo.Size._fields_ = [
            ("VirtualSize", vhdutils.wintypes.ULARGE_INTEGER),
            ("PhysicalSize", vhdutils.wintypes.ULARGE_INTEGER)]
        fake_info.VhdInfo.Size.VirtualSize = mock.sentinel.virt_size
        fake_info.VhdInfo.Size.PhysicalSize = mock.sentinel.phys_size

        ret_val = self._vhdutils._parse_vhd_info(fake_info,
                                                 fake_info_member)
        expected = {'VirtualSize': mock.sentinel.virt_size,
                    'PhysicalSize': mock.sentinel.phys_size}

        self.assertEqual(expected, ret_val)

    def test_parse_vhd_provider_subtype_member(self):
        fake_info_member = (
            vdisk_const.GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE)
        fake_info = mock.Mock()
        fake_info.VhdInfo.ProviderSubtype = mock.sentinel.provider_subtype

        ret_val = self._vhdutils._parse_vhd_info(fake_info, fake_info_member)
        expected = {'ProviderSubtype': mock.sentinel.provider_subtype}

        self.assertEqual(expected, ret_val)

    @mock.patch.object(vhdutils.VHDUtils, 'get_vhd_info')
    def test_get_vhd_size(self, mock_get_vhd_info):
        ret_val = self._vhdutils.get_vhd_size(mock.sentinel.vhd_path)

        self.assertEqual(mock_get_vhd_info.return_value, ret_val)
        mock_get_vhd_info.assert_called_once_with(
            mock.sentinel.vhd_path,
            [vdisk_const.GET_VIRTUAL_DISK_INFO_SIZE])

    @mock.patch.object(vhdutils.VHDUtils, 'get_vhd_info')
    def test_get_vhd_parent_path(self, mock_get_vhd_info):
        mock_get_vhd_info.return_value = {
            'ParentPath': mock.sentinel.parent_path}

        ret_val = self._vhdutils.get_vhd_parent_path(mock.sentinel.vhd_path)

        self.assertEqual(mock.sentinel.parent_path, ret_val)
        mock_get_vhd_info.assert_called_once_with(
            mock.sentinel.vhd_path,
            [vdisk_const.GET_VIRTUAL_DISK_INFO_PARENT_LOCATION])

    @mock.patch.object(vhdutils.VHDUtils, 'get_vhd_info')
    def test_get_vhd_type(self, mock_get_vhd_info):
        mock_get_vhd_info.return_value = {
            'ProviderSubtype': mock.sentinel.provider_subtype}

        ret_val = self._vhdutils.get_vhd_type(mock.sentinel.vhd_path)

        self.assertEqual(mock.sentinel.provider_subtype, ret_val)
        mock_get_vhd_info.assert_called_once_with(
            mock.sentinel.vhd_path,
            [vdisk_const.GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE])

    @mock.patch.object(vhdutils.VHDUtils, '_open')
    @mock.patch.object(vhdutils.VHDUtils, '_close')
    @mock.patch('os.remove')
    def test_merge_vhd(self, mock_remove, mock_close, mock_open):
        open_params_struct = (
            self._vdisk_struct.Win32_OPEN_VIRTUAL_DISK_PARAMETERS_V1)
        merge_params_struct = (
            self._vdisk_struct.Win32_MERGE_VIRTUAL_DISK_PARAMETERS)

        fake_open_params = open_params_struct.return_value
        fake_merge_params = merge_params_struct.return_value
        mock_open.return_value = mock.sentinel.handle

        self._vhdutils.merge_vhd(mock.sentinel.vhd_path)

        open_params_struct.assert_called_once_with(RWDepth=2)
        mock_open.assert_called_once_with(
            mock.sentinel.vhd_path,
            open_params=self._ctypes.byref(fake_open_params))
        merge_params_struct.assert_called_once_with(MergeDepth=1)

        self._mock_run.assert_called_once_with(
            vhdutils.virtdisk.MergeVirtualDisk,
            mock.sentinel.handle,
            None,
            self._ctypes.byref(fake_merge_params),
            None,
            **self._run_args)
        mock_remove.assert_called_once_with(
            mock.sentinel.vhd_path)
        mock_close.assert_called_once_with(mock.sentinel.handle)

    @mock.patch.object(vhdutils.VHDUtils, '_open')
    @mock.patch.object(vhdutils.VHDUtils, '_close')
    def test_reconnect_parent_vhd(self, mock_close, mock_open):
        set_vdisk_info_struct = (
            self._vdisk_struct.Win32_SET_VIRTUAL_DISK_INFO_PARAMETERS)
        open_params_struct = (
            self._vdisk_struct.Win32_OPEN_VIRTUAL_DISK_PARAMETERS_V2)

        fake_set_params = set_vdisk_info_struct.return_value
        fake_open_params = open_params_struct.return_value
        mock_open.return_value = mock.sentinel.handle

        self._vhdutils.reconnect_parent_vhd(mock.sentinel.vhd_path,
                                            mock.sentinel.parent_path)

        open_params_struct.assert_called_once_with(GetInfoOnly=False)
        self._vhdutils._open.assert_called_once_with(
            mock.sentinel.vhd_path,
            open_flag=vdisk_const.OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS,
            open_access_mask=None,
            open_params=vhdutils.ctypes.byref(fake_open_params))
        set_vdisk_info_struct.assert_called_once_with(
            ParentFilePath=mock.sentinel.parent_path)

        self._mock_run.assert_called_once_with(
            vhdutils.virtdisk.SetVirtualDiskInformation,
            mock.sentinel.handle,
            vhdutils.ctypes.byref(fake_set_params),
            **self._run_args)
        mock_close.assert_called_once_with(mock.sentinel.handle)

    @mock.patch.object(vhdutils.VHDUtils, 'get_internal_vhd_size_by_file_size')
    @mock.patch.object(vhdutils.VHDUtils, '_resize_vhd')
    def _test_resize_vhd(self, mock_resize_helper, mock_get_internal_size,
                        is_file_max_size=True):
        self._vhdutils.resize_vhd(mock.sentinel.vhd_path,
                                  mock.sentinel.new_size,
                                  is_file_max_size)

        if is_file_max_size:
            mock_get_internal_size.assert_called_once_with(
                mock.sentinel.vhd_path, mock.sentinel.new_size)
            expected_new_size = mock_get_internal_size.return_value
        else:
            expected_new_size = mock.sentinel.new_size

        mock_resize_helper.assert_called_once_with(mock.sentinel.vhd_path,
                                                   expected_new_size)

    def test_resize_vhd_specifying_internal_size(self):
        self._test_resize_vhd(is_file_max_size=False)

    def test_resize_vhd_specifying_file_max_size(self):
        self._test_resize_vhd()

    @mock.patch.object(vhdutils.VHDUtils, '_open')
    @mock.patch.object(vhdutils.VHDUtils, '_close')
    def test_resize_vhd_helper(self, mock_close, mock_open):
        resize_vdisk_struct = (
            self._vdisk_struct.Win32_RESIZE_VIRTUAL_DISK_PARAMETERS)
        fake_params = resize_vdisk_struct.return_value

        mock_open.return_value = mock.sentinel.handle

        self._vhdutils._resize_vhd(mock.sentinel.vhd_path,
                                   mock.sentinel.new_size)

        resize_vdisk_struct.assert_called_once_with(
            NewSize=mock.sentinel.new_size)
        self._mock_run.assert_called_once_with(
            vhdutils.virtdisk.ResizeVirtualDisk,
            mock.sentinel.handle,
            None,
            vhdutils.ctypes.byref(fake_params),
            None,
            **self._run_args)
        mock_close.assert_called_once_with(mock.sentinel.handle)

    @mock.patch.object(vhdutils.VHDUtils, 'get_vhd_info')
    @mock.patch.object(vhdutils.VHDUtils,
                       '_get_internal_vhd_size_by_file_size')
    @mock.patch.object(vhdutils.VHDUtils,
                       '_get_internal_vhdx_size_by_file_size')
    def _test_get_int_sz_by_file_size(
            self, mock_get_vhdx_int_size,
            mock_get_vhd_int_size, mock_get_vhd_info,
            vhd_dev_id=vdisk_const.VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
            vhd_type=constants.VHD_TYPE_DYNAMIC):
        fake_vhd_info = dict(ProviderSubtype=vhd_type,
                             ParentPath=mock.sentinel.parent_path,
                             DeviceId=vhd_dev_id)
        mock_get_vhd_info.side_effect = [fake_vhd_info]
        exppected_vhd_info_calls = [mock.call(mock.sentinel.vhd_path)]
        expected_vhd_checked = mock.sentinel.vhd_path
        expected_checked_vhd_info = fake_vhd_info

        if vhd_type == constants.VHD_TYPE_DIFFERENCING:
            expected_checked_vhd_info = dict(
                fake_vhd_info, vhd_type=constants.VHD_TYPE_DYNAMIC)
            mock_get_vhd_info.side_effect.append(
                expected_checked_vhd_info)
            exppected_vhd_info_calls.append(
                mock.call(mock.sentinel.parent_path))
            expected_vhd_checked = mock.sentinel.parent_path

        is_vhd = vhd_dev_id == vdisk_const.VIRTUAL_STORAGE_TYPE_DEVICE_VHD
        expected_helper = (mock_get_vhd_int_size
                           if is_vhd
                           else mock_get_vhdx_int_size)

        ret_val = self._vhdutils.get_internal_vhd_size_by_file_size(
            mock.sentinel.vhd_path, mock.sentinel.vhd_size)

        mock_get_vhd_info.assert_has_calls(exppected_vhd_info_calls)
        expected_helper.assert_called_once_with(expected_vhd_checked,
                                                mock.sentinel.vhd_size,
                                                expected_checked_vhd_info)
        self.assertEqual(expected_helper.return_value, ret_val)

    def test_get_int_sz_by_file_size_vhd(self):
        self._test_get_int_sz_by_file_size()

    def test_get_int_sz_by_file_size_vhdx(self):
        self._test_get_int_sz_by_file_size(
            vhd_dev_id=vdisk_const.VIRTUAL_STORAGE_TYPE_DEVICE_VHDX)

    def test_get_int_sz_by_file_size_differencing(self):
        self._test_get_int_sz_by_file_size(
            vhd_dev_id=vdisk_const.VIRTUAL_STORAGE_TYPE_DEVICE_VHDX)

    def _mocked_get_internal_vhd_size(self, root_vhd_size, vhd_type):
        fake_vhd_info = dict(ProviderSubtype=vhd_type,
                             BlockSize=2097152,
                             ParentPath=mock.sentinel.parent_path)

        return self._vhdutils._get_internal_vhd_size_by_file_size(
            mock.sentinel.vhd_path, root_vhd_size, fake_vhd_info)

    def test_get_internal_vhd_size_by_file_size_fixed(self):
        root_vhd_size = 1 << 30
        real_size = self._mocked_get_internal_vhd_size(
            root_vhd_size=root_vhd_size,
            vhd_type=constants.VHD_TYPE_FIXED)

        expected_vhd_size = root_vhd_size - 512
        self.assertEqual(expected_vhd_size, real_size)

    def test_get_internal_vhd_size_by_file_size_dynamic(self):
        root_vhd_size = 20 << 30
        real_size = self._mocked_get_internal_vhd_size(
            root_vhd_size=root_vhd_size,
            vhd_type=constants.VHD_TYPE_DYNAMIC)

        expected_md_size = 43008
        expected_vhd_size = root_vhd_size - expected_md_size
        self.assertEqual(expected_vhd_size, real_size)

    @mock.patch.object(vhdutils.VHDUtils, '_get_vhdx_log_size')
    @mock.patch.object(vhdutils.VHDUtils, '_get_vhdx_metadata_size_and_offset')
    def test_get_vhdx_internal_size(self, mock_get_vhdx_md_sz_and_off,
                                    mock_get_vhdx_log_sz):
        self._mock_open()
        fake_log_sz = 1 << 20
        fake_block_sz = 32 << 20
        fake_md_sz = 1 << 20
        fake_logical_sector_sz = 4096
        new_vhd_sz = 1 << 30
        # We expect less than a block to be reserved for internal metadata.
        expected_max_int_sz = new_vhd_sz - fake_block_sz

        fake_vhd_info = dict(LogicalSectorSize=fake_logical_sector_sz,
                             BlockSize=fake_block_sz)

        mock_get_vhdx_log_sz.return_value = fake_log_sz
        mock_get_vhdx_md_sz_and_off.return_value = fake_md_sz, None

        internal_size = self._vhdutils._get_internal_vhdx_size_by_file_size(
            mock.sentinel.vhd_path, new_vhd_sz, fake_vhd_info)

        self.assertEqual(expected_max_int_sz, internal_size)

    def test_get_vhdx_internal_size_exception(self):
        mock_open = self._mock_open()
        mock_open.side_effect = IOError
        func = self._vhdutils._get_internal_vhdx_size_by_file_size
        self.assertRaises(exceptions.VHDException,
                          func,
                          mock.sentinel.vhd_path,
                          mock.sentinel.vhd_size,
                          mock.sentinel.vhd_info)

    def _get_mock_file_handle(self, *args):
        mock_file_handle = mock.Mock()
        mock_file_handle.read.side_effect = args
        return mock_file_handle

    def test_get_vhdx_current_header(self):
        # The current header has the maximum sequence number.
        fake_seq_numbers = ['\x01\x00\x00\x00\x00\x00\x00\x00',
                            '\x02\x00\x00\x00\x00\x00\x00\x00']
        mock_handle = self._get_mock_file_handle(*fake_seq_numbers)

        offset = self._vhdutils._get_vhdx_current_header_offset(mock_handle)

        self.assertEqual(vdisk_const.VHDX_HEADER_OFFSETS[1], offset)

    @mock.patch.object(vhdutils.VHDUtils, '_get_vhdx_current_header_offset')
    def test_get_log_size(self, mock_get_vhdx_curr_hd_offset):
        fake_curr_header_offset = vdisk_const.VHDX_HEADER_OFFSETS[0]
        fake_log_sz = '\x01\x00\x00\x00'

        mock_get_vhdx_curr_hd_offset.return_value = fake_curr_header_offset
        mock_handle = self._get_mock_file_handle(fake_log_sz)

        log_size = self._vhdutils._get_vhdx_log_size(mock_handle)

        self.assertEqual(log_size, 1)

    def test_get_vhdx_metadata_size(self):
        fake_md_offset = '\x01\x00\x00\x00\x00\x00\x00\x00'
        fake_md_sz = '\x01\x00\x00\x00'

        mock_handle = self._get_mock_file_handle(fake_md_offset,
                                                      fake_md_sz)

        md_sz, md_offset = self._vhdutils._get_vhdx_metadata_size_and_offset(
            mock_handle)

        self.assertEqual(1, md_sz)
        self.assertEqual(1, md_offset)

    @mock.patch.object(vhdutils.VHDUtils, 'convert_vhd')
    @mock.patch.object(os, 'unlink')
    @mock.patch.object(os, 'rename')
    def test_flatten_vhd(self, mock_rename, mock_unlink, mock_convert):
        fake_vhd_path = r'C:\test.vhd'
        expected_tmp_path = r'C:\test.tmp.vhd'

        self._vhdutils.flatten_vhd(fake_vhd_path)

        mock_convert.assert_called_once_with(fake_vhd_path, expected_tmp_path)
        mock_unlink.assert_called_once_with(fake_vhd_path)
        mock_rename.assert_called_once_with(expected_tmp_path, fake_vhd_path)

    def test_get_best_supported_vhd_format(self):
        fmt = self._vhdutils.get_best_supported_vhd_format()
        self.assertEqual(constants.DISK_FORMAT_VHDX, fmt)
