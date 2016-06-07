# Copyright 2015 Cloudbase Solutions SRL
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

"""
Unit tests for the os_win._utils module.
"""

import mock
from oslotest import base

from os_win import _utils
from os_win import exceptions


class UtilsTestCase(base.BaseTestCase):

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_execute(self, mock_execute):
        _utils.execute(mock.sentinel.cmd, kwarg=mock.sentinel.kwarg)
        mock_execute.assert_called_once_with(mock.sentinel.cmd,
                                             kwarg=mock.sentinel.kwarg)

    def test_parse_server_string(self):
        result = _utils.parse_server_string('::1')
        self.assertEqual(('::1', ''), result)
        result = _utils.parse_server_string('[::1]:8773')
        self.assertEqual(('::1', '8773'), result)
        result = _utils.parse_server_string('2001:db8::192.168.1.1')
        self.assertEqual(('2001:db8::192.168.1.1', ''), result)
        result = _utils.parse_server_string('[2001:db8::192.168.1.1]:8773')
        self.assertEqual(('2001:db8::192.168.1.1', '8773'), result)
        result = _utils.parse_server_string('192.168.1.1')
        self.assertEqual(('192.168.1.1', ''), result)
        result = _utils.parse_server_string('192.168.1.2:8773')
        self.assertEqual(('192.168.1.2', '8773'), result)
        result = _utils.parse_server_string('192.168.1.3')
        self.assertEqual(('192.168.1.3', ''), result)
        result = _utils.parse_server_string('www.example.com:8443')
        self.assertEqual(('www.example.com', '8443'), result)
        result = _utils.parse_server_string('www.example.com')
        self.assertEqual(('www.example.com', ''), result)
        # error case
        result = _utils.parse_server_string('www.exa:mple.com:8443')
        self.assertEqual(('', ''), result)
        result = _utils.parse_server_string('')
        self.assertEqual(('', ''), result)

    def _get_fake_func_with_retry_decorator(self, side_effect,
                                            *args, **kwargs):
        func_side_effect = mock.Mock(side_effect=side_effect)

        @_utils.retry_decorator(*args, **kwargs)
        def fake_func(*_args, **_kwargs):
            return func_side_effect(*_args, **_kwargs)

        return fake_func, func_side_effect

    @mock.patch('time.sleep')
    def test_retry_decorator(self, mock_sleep):
        err_code = 1
        max_retry_count = 5
        max_sleep_time = 4

        raised_exc = exceptions.Win32Exception(message='fake_exc',
                                               error_code=err_code)
        side_effect = [raised_exc] * max_retry_count
        side_effect.append(mock.sentinel.ret_val)

        fake_func = self._get_fake_func_with_retry_decorator(
            error_codes=err_code,
            exceptions=exceptions.Win32Exception,
            max_retry_count=max_retry_count,
            max_sleep_time=max_sleep_time,
            side_effect=side_effect)[0]

        ret_val = fake_func()
        self.assertEqual(mock.sentinel.ret_val, ret_val)
        mock_sleep.assert_has_calls([mock.call(sleep_time)
                                     for sleep_time in [1, 2, 3, 4, 4]])

    @mock.patch('time.sleep')
    def _test_retry_decorator_no_retry(self, mock_sleep,
                                       expected_exceptions=(),
                                       expected_error_codes=()):
        err_code = 1
        raised_exc = exceptions.Win32Exception(message='fake_exc',
                                               error_code=err_code)
        fake_func, fake_func_side_effect = (
            self._get_fake_func_with_retry_decorator(
                error_codes=expected_error_codes,
                exceptions=expected_exceptions,
                side_effect=raised_exc))

        self.assertRaises(exceptions.Win32Exception,
                          fake_func, mock.sentinel.arg,
                          fake_kwarg=mock.sentinel.kwarg)

        self.assertFalse(mock_sleep.called)
        fake_func_side_effect.assert_called_once_with(
            mock.sentinel.arg, fake_kwarg=mock.sentinel.kwarg)

    def test_retry_decorator_unexpected_err_code(self):
        self._test_retry_decorator_no_retry(
            expected_exceptions=exceptions.Win32Exception,
            expected_error_codes=2)

    def test_retry_decorator_unexpected_exc(self):
        self._test_retry_decorator_no_retry(
            expected_exceptions=(IOError, AttributeError))

    @mock.patch('socket.getaddrinfo')
    def test_get_ips(self, mock_getaddrinfo):
        ips = ['1.2.3.4', '5.6.7.8']
        mock_getaddrinfo.return_value = [
            (None, None, None, None, (ip, 0)) for ip in ips]

        resulted_ips = _utils.get_ips(mock.sentinel.addr)
        self.assertEqual(ips, resulted_ips)

        mock_getaddrinfo.assert_called_once_with(
            mock.sentinel.addr, None, 0, 0, 0)
