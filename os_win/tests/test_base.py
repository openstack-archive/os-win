# Copyright 2015 Cloudbase Solutions Srl
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

import mock
from oslotest import base
from six.moves import builtins


class FakeWMIExc(Exception):
    def __init__(self, hresult=None):
        excepinfo = [None] * 5 + [hresult]
        self.com_error = mock.Mock(excepinfo=excepinfo)
        super(FakeWMIExc, self).__init__()


class OsWinBaseTestCase(base.BaseTestCase):
    def setUp(self):
        super(OsWinBaseTestCase, self).setUp()

        self._mock_wmi = mock.MagicMock()
        self._mock_wmi.x_wmi = FakeWMIExc

        mock_os = mock.MagicMock(Version='6.3.0')
        self._mock_wmi.WMI.return_value.Win32_OperatingSystem.return_value = (
            [mock_os])
        wmi_patcher = mock.patch.object(builtins, 'wmi', create=True,
                                        new=self._mock_wmi)
        wmi_patcher.start()
        self.addCleanup(mock.patch.stopall)
