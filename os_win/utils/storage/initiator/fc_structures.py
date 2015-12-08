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


HBA_HANDLE = ctypes.c_uint32
HBA_PortType = ctypes.c_uint32
HBA_PortSpeed = ctypes.c_uint32
HBA_PortState = ctypes.c_uint32
HBA_COS = ctypes.c_uint32
HBA_WWN = ctypes.c_ubyte * 8
HBA_FC4Types = ctypes.c_uint32 * 32
HBA_FCPBindingType = ctypes.c_int


class HBA_PortAttributes(ctypes.Structure):
    _fields_ = [('NodeWWN', HBA_WWN),
                ('PortWWN', HBA_WWN),
                ('PortFcId', ctypes.c_uint32),
                ('PortType', HBA_PortType),
                ('PortState', HBA_PortState),
                ('PortSupportedClassofService', HBA_COS),
                ('PortSupportedFc4Types', HBA_FC4Types),
                ('PortSymbolicName', ctypes.c_char * 256),
                ('OSDeviceName', ctypes.c_char * 256),
                ('PortSupportedSpeed', HBA_PortSpeed),
                ('PortSpeed', HBA_PortSpeed),
                ('PortMaxFrameSize', ctypes.c_uint32),
                ('FabricName', HBA_WWN),
                ('NumberOfDiscoveredPorts', ctypes.c_uint32)]


class HBA_FCPId(ctypes.Structure):
    _fields_ = [('FcId', ctypes.c_uint32),
                ('NodeWWN', HBA_WWN),
                ('PortWWN', HBA_WWN),
                ('FcpLun', ctypes.c_uint64)]


class HBA_ScsiId(ctypes.Structure):
    _fields_ = [('OSDeviceName', ctypes.c_char * 256),
                ('ScsiBusNumber', ctypes.c_uint32),
                ('ScsiTargetNumber', ctypes.c_uint32),
                ('ScsiOSLun', ctypes.c_uint32)]


class HBA_FCPScsiEntry(ctypes.Structure):
    _fields_ = [('ScsiId', HBA_ScsiId),
                ('FcpId', HBA_FCPId)]


def get_target_mapping_struct(entry_count=0):
    class HBA_FCPTargetMapping(ctypes.Structure):
        _fields_ = [('NumberOfEntries', ctypes.c_uint32),
                    ('Entries', HBA_FCPScsiEntry * entry_count)]

        def __init__(self, entry_count):
            self.NumberOfEntries = entry_count
            self.Entries = (HBA_FCPScsiEntry * entry_count)()

    return HBA_FCPTargetMapping(entry_count)


class HBA_AdapterAttributes(ctypes.Structure):
    _fields_ = [('Manufacturer', ctypes.c_char * 64),
                ('SerialNumber', ctypes.c_char * 64),
                ('Model', ctypes.c_char * 256),
                ('ModelDescription', ctypes.c_char * 256),
                ('NodeWWN', HBA_WWN),
                ('NodeSymbolicName', ctypes.c_char * 256),
                ('HardwareVersion', ctypes.c_char * 256),
                ('DriverVersion', ctypes.c_char * 256),
                ('OptionROMVersion', ctypes.c_char * 256),
                ('FirmwareVersion', ctypes.c_char * 256),
                ('VendorSpecificID', ctypes.c_uint32),
                ('NumberOfPorts', ctypes.c_uint32),
                ('DriverName', ctypes.c_char * 256)]
