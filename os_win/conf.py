# Copyright 2017 Cloudbase Solutions Srl
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

from oslo_config import cfg

os_win_group = 'os_win'

os_win_opts = [
    cfg.StrOpt('hbaapi_lib_path',
               default='hbaapi.dll',
               help='Fibre Channel hbaapi library path. If no custom hbaapi '
                    'library is requested, the default one will be used.'),
    cfg.BoolOpt('cache_temporary_wmi_objects',
                default=True,
                help='Caches temporary WMI objects in order to increase '
                     'performance. This only affects networkutils, where '
                     'almost all operations require a reference to a '
                     'switch port. The cached objects are no longer valid '
                     'if the VM they are associated with is destroyed.'),
]

CONF = cfg.CONF
CONF.register_opts(os_win_opts, os_win_group)


def list_opts():
    return [(os_win_group, os_win_opts)]
