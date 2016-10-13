# Copyright 2014 Cloudbase Solutions Srl
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
#    under the License.import mock

import mock
from oslotest import base

import os
import six

from os_win import constants
from os_win import exceptions
from os_win.utils.io import ioutils


class IOThreadTestCase(base.BaseTestCase):
    _FAKE_SRC = r'fake_source_file'
    _FAKE_DEST = r'fake_dest_file'
    _FAKE_MAX_BYTES = 1

    def setUp(self):
        self._iothread = ioutils.IOThread(
            self._FAKE_SRC, self._FAKE_DEST, self._FAKE_MAX_BYTES)
        super(IOThreadTestCase, self).setUp()

    @mock.patch.object(six.moves.builtins, 'open')
    @mock.patch('os.rename')
    @mock.patch('os.path.exists')
    @mock.patch('os.remove')
    def test_copy(self, fake_remove, fake_exists, fake_rename, fake_open):
        fake_data = 'a'
        fake_src = mock.Mock()
        fake_dest = mock.Mock()

        fake_src.read.return_value = fake_data
        fake_dest.tell.return_value = 0
        fake_exists.return_value = True

        mock_context_manager = mock.MagicMock()
        fake_open.return_value = mock_context_manager
        mock_context_manager.__enter__.side_effect = [fake_src, fake_dest]
        self._iothread._stopped.isSet = mock.Mock(side_effect=[False, True])

        self._iothread._copy()

        fake_dest.seek.assert_called_once_with(0, os.SEEK_END)
        fake_dest.write.assert_called_once_with(fake_data)
        fake_dest.close.assert_called_once_with()
        fake_rename.assert_called_once_with(
            self._iothread._dest, self._iothread._dest_archive)
        fake_remove.assert_called_once_with(
            self._iothread._dest_archive)
        self.assertEqual(3, fake_open.call_count)


class IOUtilsTestCase(base.BaseTestCase):
    def setUp(self):
        super(IOUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        self._ioutils = ioutils.IOUtils()
        self._ioutils._win32_utils = mock.Mock()

        self._mock_run = self._ioutils._win32_utils.run_and_check_output
        self._run_args = dict(kernel32_lib_func=True,
                              failure_exc=exceptions.Win32IOException,
                              eventlet_nonblocking_mode=False)

        self.addCleanup(mock.patch.stopall)

    def _setup_lib_mocks(self):
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")
        self._ctypes.c_wchar_p = lambda x: (x, "c_wchar_p")

        mock.patch.multiple(ioutils,
                            ctypes=self._ctypes, kernel32=mock.DEFAULT,
                            create=True).start()

    def test_run_and_check_output(self):
        ret_val = self._ioutils._run_and_check_output(
            mock.sentinel.func, mock.sentinel.arg)

        self._mock_run.assert_called_once_with(mock.sentinel.func,
                                               mock.sentinel.arg,
                                               **self._run_args)
        self.assertEqual(self._mock_run.return_value, ret_val)

    def test_wait_named_pipe(self):
        fake_timeout_s = 10
        self._ioutils.wait_named_pipe(mock.sentinel.pipe_name,
                                      timeout=fake_timeout_s)

        self._mock_run.assert_called_once_with(
            ioutils.kernel32.WaitNamedPipeW,
            self._ctypes.c_wchar_p(mock.sentinel.pipe_name),
            fake_timeout_s * 1000,
            **self._run_args)

    def test_open(self):
        handle = self._ioutils.open(mock.sentinel.path,
                                    mock.sentinel.access,
                                    mock.sentinel.share_mode,
                                    mock.sentinel.create_disposition,
                                    mock.sentinel.flags)

        self._mock_run.assert_called_once_with(
            ioutils.kernel32.CreateFileW,
            self._ctypes.c_wchar_p(mock.sentinel.path),
            mock.sentinel.access,
            mock.sentinel.share_mode,
            None,
            mock.sentinel.create_disposition,
            mock.sentinel.flags,
            None,
            error_ret_vals=[ioutils.INVALID_HANDLE_VALUE],
            **self._run_args)
        self.assertEqual(self._mock_run.return_value, handle)

    def test_cancel_io(self):
        self._ioutils.cancel_io(mock.sentinel.handle,
                                mock.sentinel.overlapped_struct,
                                ignore_invalid_handle=True)

        expected_ignored_err_codes = [ioutils.ERROR_NOT_FOUND,
                                      ioutils.ERROR_INVALID_HANDLE]

        self._mock_run.assert_called_once_with(
            ioutils.kernel32.CancelIoEx,
            mock.sentinel.handle,
            self._ctypes.byref(mock.sentinel.overlapped_struct),
            ignored_error_codes=expected_ignored_err_codes,
            **self._run_args)

    def test_close_handle(self):
        self._ioutils.close_handle(mock.sentinel.handle)

        self._mock_run.assert_called_once_with(ioutils.kernel32.CloseHandle,
                                               mock.sentinel.handle,
                                               **self._run_args)

    def test_wait_io_completion(self):
        self._ioutils._wait_io_completion(mock.sentinel.event)

        self._mock_run.assert_called_once_with(
            ioutils.kernel32.WaitForSingleObjectEx,
            mock.sentinel.event,
            ioutils.WAIT_INFINITE_TIMEOUT,
            True,
            error_ret_vals=[ioutils.WAIT_FAILED],
            **self._run_args)

    def test_set_event(self):
        self._ioutils.set_event(mock.sentinel.event)

        self._mock_run.assert_called_once_with(ioutils.kernel32.SetEvent,
                                               mock.sentinel.event,
                                               **self._run_args)

    def test_reset_event(self):
        self._ioutils._reset_event(mock.sentinel.event)

        self._mock_run.assert_called_once_with(ioutils.kernel32.ResetEvent,
                                               mock.sentinel.event,
                                               **self._run_args)

    def test_create_event(self):
        event = self._ioutils._create_event(mock.sentinel.event_attributes,
                                            mock.sentinel.manual_reset,
                                            mock.sentinel.initial_state,
                                            mock.sentinel.name)

        self._mock_run.assert_called_once_with(ioutils.kernel32.CreateEventW,
                                               mock.sentinel.event_attributes,
                                               mock.sentinel.manual_reset,
                                               mock.sentinel.initial_state,
                                               mock.sentinel.name,
                                               error_ret_vals=[None],
                                               **self._run_args)
        self.assertEqual(self._mock_run.return_value, event)

    @mock.patch.object(ioutils, 'LPOVERLAPPED', create=True)
    @mock.patch.object(ioutils, 'LPOVERLAPPED_COMPLETION_ROUTINE',
                       lambda x: x, create=True)
    @mock.patch.object(ioutils.IOUtils, 'set_event')
    def test_get_completion_routine(self, mock_set_event,
                                    mock_LPOVERLAPPED):
        mock_callback = mock.Mock()

        compl_routine = self._ioutils.get_completion_routine(mock_callback)
        compl_routine(mock.sentinel.error_code,
                      mock.sentinel.num_bytes,
                      mock.sentinel.lpOverLapped)

        self._ctypes.cast.assert_called_once_with(mock.sentinel.lpOverLapped,
                                                  ioutils.LPOVERLAPPED)
        mock_overlapped_struct = self._ctypes.cast.return_value.contents
        mock_set_event.assert_called_once_with(mock_overlapped_struct.hEvent)
        mock_callback.assert_called_once_with(mock.sentinel.num_bytes)

    @mock.patch.object(ioutils, 'OVERLAPPED', create=True)
    @mock.patch.object(ioutils.IOUtils, '_create_event')
    def test_get_new_overlapped_structure(self, mock_create_event,
                                          mock_OVERLAPPED):
        overlapped_struct = self._ioutils.get_new_overlapped_structure()

        self.assertEqual(mock_OVERLAPPED.return_value, overlapped_struct)
        self.assertEqual(mock_create_event.return_value,
                         overlapped_struct.hEvent)

    @mock.patch.object(ioutils.IOUtils, '_reset_event')
    @mock.patch.object(ioutils.IOUtils, '_wait_io_completion')
    def test_read(self, mock_wait_io_completion, mock_reset_event):
        mock_overlapped_struct = mock.Mock()
        mock_event = mock_overlapped_struct.hEvent
        self._ioutils.read(mock.sentinel.handle, mock.sentinel.buff,
                           mock.sentinel.num_bytes,
                           mock_overlapped_struct,
                           mock.sentinel.compl_routine)

        mock_reset_event.assert_called_once_with(mock_event)
        self._mock_run.assert_called_once_with(ioutils.kernel32.ReadFileEx,
                                               mock.sentinel.handle,
                                               mock.sentinel.buff,
                                               mock.sentinel.num_bytes,
                                               self._ctypes.byref(
                                                   mock_overlapped_struct),
                                               mock.sentinel.compl_routine,
                                               **self._run_args)
        mock_wait_io_completion.assert_called_once_with(mock_event)

    @mock.patch.object(ioutils.IOUtils, '_reset_event')
    @mock.patch.object(ioutils.IOUtils, '_wait_io_completion')
    def test_write(self, mock_wait_io_completion, mock_reset_event):
        mock_overlapped_struct = mock.Mock()
        mock_event = mock_overlapped_struct.hEvent
        self._ioutils.write(mock.sentinel.handle, mock.sentinel.buff,
                            mock.sentinel.num_bytes,
                            mock_overlapped_struct,
                            mock.sentinel.compl_routine)

        mock_reset_event.assert_called_once_with(mock_event)
        self._mock_run.assert_called_once_with(ioutils.kernel32.WriteFileEx,
                                               mock.sentinel.handle,
                                               mock.sentinel.buff,
                                               mock.sentinel.num_bytes,
                                               self._ctypes.byref(
                                                   mock_overlapped_struct),
                                               mock.sentinel.compl_routine,
                                               **self._run_args)
        mock_wait_io_completion.assert_called_once_with(mock_event)

    def test_buffer_ops(self):
        mock.patch.stopall()

        fake_data = 'fake data'

        buff = self._ioutils.get_buffer(len(fake_data), data=fake_data)
        buff_data = self._ioutils.get_buffer_data(buff, len(fake_data))

        self.assertEqual(six.b(fake_data), buff_data)


class IOQueueTestCase(base.BaseTestCase):
    def setUp(self):
        super(IOQueueTestCase, self).setUp()

        self._mock_queue = mock.Mock()
        queue_patcher = mock.patch.object(ioutils.Queue, 'Queue',
                                          new=self._mock_queue)
        queue_patcher.start()
        self.addCleanup(queue_patcher.stop)

        self._mock_client_connected = mock.Mock()
        self._ioqueue = ioutils.IOQueue(self._mock_client_connected)

    def test_get(self):
        self._mock_client_connected.isSet.return_value = True
        self._mock_queue.get.return_value = mock.sentinel.item

        queue_item = self._ioqueue.get(timeout=mock.sentinel.timeout)

        self._mock_queue.get.assert_called_once_with(
            self._ioqueue, timeout=mock.sentinel.timeout)
        self.assertEqual(mock.sentinel.item, queue_item)

    def _test_get_timeout(self, continue_on_timeout=True):
        self._mock_client_connected.isSet.side_effect = [True, True, False]
        self._mock_queue.get.side_effect = ioutils.Queue.Empty

        queue_item = self._ioqueue.get(timeout=mock.sentinel.timeout,
                                       continue_on_timeout=continue_on_timeout)

        expected_calls_number = 2 if continue_on_timeout else 1
        self._mock_queue.get.assert_has_calls(
            [mock.call(self._ioqueue, timeout=mock.sentinel.timeout)] *
            expected_calls_number)
        self.assertIsNone(queue_item)

    def test_get_continue_on_timeout(self):
        # Test that the queue blocks as long
        # as the client connected event is set.
        self._test_get_timeout()

    def test_get_break_on_timeout(self):
        self._test_get_timeout(continue_on_timeout=False)

    def test_put(self):
        self._mock_client_connected.isSet.side_effect = [True, True, False]
        self._mock_queue.put.side_effect = ioutils.Queue.Full

        self._ioqueue.put(mock.sentinel.item,
                          timeout=mock.sentinel.timeout)

        self._mock_queue.put.assert_has_calls(
            [mock.call(self._ioqueue, mock.sentinel.item,
                       timeout=mock.sentinel.timeout)] * 2)

    @mock.patch.object(ioutils.IOQueue, 'get')
    def _test_get_burst(self, mock_get,
                        exceeded_max_size=False):
        fake_data = 'fake_data'

        mock_get.side_effect = [fake_data, fake_data, None]

        if exceeded_max_size:
            max_size = 0
        else:
            max_size = constants.SERIAL_CONSOLE_BUFFER_SIZE

        ret_val = self._ioqueue.get_burst(
            timeout=mock.sentinel.timeout,
            burst_timeout=mock.sentinel.burst_timeout,
            max_size=max_size)

        expected_calls = [mock.call(timeout=mock.sentinel.timeout)]
        expected_ret_val = fake_data

        if not exceeded_max_size:
            expected_calls.append(
                mock.call(timeout=mock.sentinel.burst_timeout,
                          continue_on_timeout=False))
            expected_ret_val += fake_data

        mock_get.assert_has_calls(expected_calls)
        self.assertEqual(expected_ret_val, ret_val)

    def test_get_burst(self):
        self._test_get_burst()

    def test_get_burst_exceeded_size(self):
        self._test_get_burst(exceeded_max_size=True)
