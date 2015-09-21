# Copyright 2013 Cloudbase Solutions Srl
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
from oslo_log import log as logging

from os_win._i18n import _, _LW  # noqa
from os_win import exceptions
from os_win.utils.compute import livemigrationutils
from os_win.utils.compute import rdpconsoleutils
from os_win.utils.compute import rdpconsoleutilsv2
from os_win.utils.compute import vmutils
from os_win.utils.compute import vmutilsv2
from os_win.utils import hostutils
from os_win.utils import hostutilsv2
from os_win.utils.network import networkutils
from os_win.utils.network import networkutilsv2
from os_win.utils import pathutils
from os_win.utils.storage import vhdutils
from os_win.utils.storage import vhdutilsv2
from os_win.utils.storage import volumeutils
from os_win.utils.storage import volumeutilsv2

hyper_opts = [
    cfg.BoolOpt('force_hyperv_utils_v1',
                default=False,
                deprecated_for_removal=True,
                help='Force V1 WMI utility classes'),
    cfg.BoolOpt('force_volumeutils_v1',
                default=False,
                help='Force V1 volume utility class'),
]

CONF = cfg.CONF
CONF.register_opts(hyper_opts, 'hyperv')

LOG = logging.getLogger(__name__)

utils = hostutils.HostUtils()


def _get_class(v1_class, v2_class, force_v1_flag):
    # V2 classes are supported starting from Hyper-V Server 2012 and
    # Windows Server 2012 (kernel version 6.2)
    if not force_v1_flag and utils.check_min_windows_version(6, 2):
        cls = v2_class
    else:
        cls = v1_class
    LOG.debug("Loading class: %(module_name)s.%(class_name)s",
              {'module_name': cls.__module__, 'class_name': cls.__name__})
    return cls


def _get_virt_utils_class(v1_class, v2_class):
    # The "root/virtualization" WMI namespace is no longer supported on
    # Windows Server / Hyper-V Server 2012 R2 / Windows 8.1
    # (kernel version 6.3) or above.
    if (CONF.hyperv.force_hyperv_utils_v1 and
            utils.check_min_windows_version(6, 3)):
        raise exceptions.HyperVException(
            _('The "force_hyperv_utils_v1" option cannot be set to "True" '
              'on Windows Server / Hyper-V Server 2012 R2 or above as the WMI '
              '"root/virtualization" namespace is no longer supported.'))
    return _get_class(v1_class, v2_class, CONF.hyperv.force_hyperv_utils_v1)


def get_vmutils(host='.'):
    return _get_virt_utils_class(vmutils.VMUtils, vmutilsv2.VMUtilsV2)(host)


def get_vhdutils():
    return _get_virt_utils_class(vhdutils.VHDUtils, vhdutilsv2.VHDUtilsV2)()


def get_networkutils():
    force_v1_flag = CONF.hyperv.force_hyperv_utils_v1
    if utils.check_min_windows_version(6, 3):
        if force_v1_flag:
            LOG.warning(_LW('V1 virtualization namespace no longer supported '
                            'on Windows Server / Hyper-V Server 2012 R2 or '
                            'above.'))
        cls = networkutilsv2.NetworkUtilsV2R2
    else:
        cls = _get_virt_utils_class(networkutils.NetworkUtils,
                                    networkutilsv2.NetworkUtilsV2)
    return cls()


def get_hostutils():
    return _get_virt_utils_class(hostutils.HostUtils,
                                 hostutilsv2.HostUtilsV2)()


def get_pathutils():
    return pathutils.PathUtils()


def get_volumeutils():
    return _get_class(volumeutils.VolumeUtils, volumeutilsv2.VolumeUtilsV2,
                      CONF.hyperv.force_volumeutils_v1)()


def get_livemigrationutils():
    return livemigrationutils.LiveMigrationUtils()


def get_rdpconsoleutils():
    return _get_virt_utils_class(rdpconsoleutils.RDPConsoleUtils,
                      rdpconsoleutilsv2.RDPConsoleUtilsV2)()
