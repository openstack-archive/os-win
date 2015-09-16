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
