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

from os_win._i18n import _, _LW
from os_win import exceptions
from os_win.utils import hostutils
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class HostUtils10(hostutils.HostUtils):

    _HGS_NAMESPACE = '//%s/Root/Microsoft/Windows/Hgs'

    def __init__(self, host='.'):
        super(HostUtils10, self).__init__(host)
        self._conn_hgs_attr = None

    @property
    def _conn_hgs(self):
        if not self._conn_hgs_attr:
            try:
                namespace = self._HGS_NAMESPACE % self._host
                self._conn_hgs_attr = self._get_wmi_conn(namespace)
            except Exception:
                raise exceptions.OSWinException(
                    _("Namespace %(namespace)s is not supported on this "
                      "Windows version.") %
                    {'namespace': namespace})

        return self._conn_hgs_attr

    def is_host_guarded(self):
        """Checks the host is guarded so it can run Shielded VMs"""

        (return_code,
         host_config) = self._conn_hgs.MSFT_HgsClientConfiguration.Get()
        if return_code:
            LOG.warning(_LW('Retrieving the local Host Guardian Service '
                            'Client configuration failed with code: %s'),
                        return_code)
            return False
        return host_config.IsHostGuarded
