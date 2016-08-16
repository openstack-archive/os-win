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

# Error codes and descriptions, as provided by iscsierr.h

from os_win._i18n import _

ISDSC_NON_SPECIFIC_ERROR = 0xEFFF0001
ISDSC_LOGIN_FAILED = 0xEFFF0002
ISDSC_CONNECTION_FAILED = 0xEFFF0003
ISDSC_INITIATOR_NODE_ALREADY_EXISTS = 0xEFFF0004
ISDSC_INITIATOR_NODE_NOT_FOUND = 0xEFFF0005
ISDSC_TARGET_MOVED_TEMPORARILY = 0xEFFF0006
ISDSC_TARGET_MOVED_PERMANENTLY = 0xEFFF0007
ISDSC_INITIATOR_ERROR = 0xEFFF0008
ISDSC_AUTHENTICATION_FAILURE = 0xEFFF0009
ISDSC_AUTHORIZATION_FAILURE = 0xEFFF000A
ISDSC_NOT_FOUND = 0xEFFF000B
ISDSC_TARGET_REMOVED = 0xEFFF000C
ISDSC_UNSUPPORTED_VERSION = 0xEFFF000D
ISDSC_TOO_MANY_CONNECTIONS = 0xEFFF000E
ISDSC_MISSING_PARAMETER = 0xEFFF000F
ISDSC_CANT_INCLUDE_IN_SESSION = 0xEFFF0010
ISDSC_SESSION_TYPE_NOT_SUPPORTED = 0xEFFF0011
ISDSC_TARGET_ERROR = 0xEFFF0012
ISDSC_SERVICE_UNAVAILABLE = 0xEFFF0013
ISDSC_OUT_OF_RESOURCES = 0xEFFF0014
ISDSC_CONNECTION_ALREADY_EXISTS = 0xEFFF0015
ISDSC_SESSION_ALREADY_EXISTS = 0xEFFF0016
ISDSC_INITIATOR_INSTANCE_NOT_FOUND = 0xEFFF0017
ISDSC_TARGET_ALREADY_EXISTS = 0xEFFF0018
ISDSC_DRIVER_BUG = 0xEFFF0019
ISDSC_INVALID_TEXT_KEY = 0xEFFF001A
ISDSC_INVALID_SENDTARGETS_TEXT = 0xEFFF001B
ISDSC_INVALID_SESSION_ID = 0xEFFF001C
ISDSC_SCSI_REQUEST_FAILED = 0xEFFF001D
ISDSC_TOO_MANY_SESSIONS = 0xEFFF001E
ISDSC_SESSION_BUSY = 0xEFFF001F
ISDSC_TARGET_MAPPING_UNAVAILABLE = 0xEFFF0020
ISDSC_ADDRESS_TYPE_NOT_SUPPORTED = 0xEFFF0021
ISDSC_LOGON_FAILED = 0xEFFF0022
ISDSC_SEND_FAILED = 0xEFFF0023
ISDSC_TRANSPORT_ERROR = 0xEFFF0024
ISDSC_VERSION_MISMATCH = 0xEFFF0025
ISDSC_TARGET_MAPPING_OUT_OF_RANGE = 0xEFFF0026
ISDSC_TARGET_PRESHAREDKEY_UNAVAILABLE = 0xEFFF0027
ISDSC_TARGET_AUTHINFO_UNAVAILABLE = 0xEFFF0028
ISDSC_TARGET_NOT_FOUND = 0xEFFF0029
ISDSC_LOGIN_USER_INFO_BAD = 0xEFFF002A
ISDSC_TARGET_MAPPING_EXISTS = 0xEFFF002B
ISDSC_HBA_SECURITY_CACHE_FULL = 0xEFFF002C
ISDSC_INVALID_PORT_NUMBER = 0xEFFF002D
ISDSC_OPERATION_NOT_ALL_SUCCESS = 0xAFFF002E
ISDSC_HBA_SECURITY_CACHE_NOT_SUPPORTED = 0xEFFF002F
ISDSC_IKE_ID_PAYLOAD_TYPE_NOT_SUPPORTED = 0xEFFF0030
ISDSC_IKE_ID_PAYLOAD_INCORRECT_SIZE = 0xEFFF0031
ISDSC_TARGET_PORTAL_ALREADY_EXISTS = 0xEFFF0032
ISDSC_TARGET_ADDRESS_ALREADY_EXISTS = 0xEFFF0033
ISDSC_NO_AUTH_INFO_AVAILABLE = 0xEFFF0034
ISDSC_NO_TUNNEL_OUTER_MODE_ADDRESS = 0xEFFF0035
ISDSC_CACHE_CORRUPTED = 0xEFFF0036
ISDSC_REQUEST_NOT_SUPPORTED = 0xEFFF0037
ISDSC_TARGET_OUT_OF_RESORCES = 0xEFFF0038
ISDSC_SERVICE_DID_NOT_RESPOND = 0xEFFF0039
ISDSC_ISNS_SERVER_NOT_FOUND = 0xEFFF003A
ISDSC_OPERATION_REQUIRES_REBOOT = 0xAFFF003B
ISDSC_NO_PORTAL_SPECIFIED = 0xEFFF003C
ISDSC_CANT_REMOVE_LAST_CONNECTION = 0xEFFF003D
ISDSC_SERVICE_NOT_RUNNING = 0xEFFF003E
ISDSC_TARGET_ALREADY_LOGGED_IN = 0xEFFF003F
ISDSC_DEVICE_BUSY_ON_SESSION = 0xEFFF0040
ISDSC_COULD_NOT_SAVE_PERSISTENT_LOGIN_DATA = 0xEFFF0041
ISDSC_COULD_NOT_REMOVE_PERSISTENT_LOGIN_DATA = 0xEFFF0042
ISDSC_PORTAL_NOT_FOUND = 0xEFFF0043
ISDSC_INITIATOR_NOT_FOUND = 0xEFFF0044
ISDSC_DISCOVERY_MECHANISM_NOT_FOUND = 0xEFFF0045
ISDSC_IPSEC_NOT_SUPPORTED_ON_OS = 0xEFFF0046
ISDSC_PERSISTENT_LOGIN_TIMEOUT = 0xEFFF0047
ISDSC_SHORT_CHAP_SECRET = 0xAFFF0048
ISDSC_EVALUATION_PEROID_EXPIRED = 0xEFFF0049
ISDSC_INVALID_CHAP_SECRET = 0xEFFF004A
ISDSC_INVALID_TARGET_CHAP_SECRET = 0xEFFF004B
ISDSC_INVALID_INITIATOR_CHAP_SECRET = 0xEFFF004C
ISDSC_INVALID_CHAP_USER_NAME = 0xEFFF004D
ISDSC_INVALID_LOGON_AUTH_TYPE = 0xEFFF004E
ISDSC_INVALID_TARGET_MAPPING = 0xEFFF004F
ISDSC_INVALID_TARGET_ID = 0xEFFF0050
ISDSC_INVALID_ISCSI_NAME = 0xEFFF0051
ISDSC_INCOMPATIBLE_ISNS_VERSION = 0xEFFF0052
ISDSC_FAILED_TO_CONFIGURE_IPSEC = 0xEFFF0053
ISDSC_BUFFER_TOO_SMALL = 0xEFFF0054
ISDSC_INVALID_LOAD_BALANCE_POLICY = 0xEFFF0055
ISDSC_INVALID_PARAMETER = 0xEFFF0056
ISDSC_DUPLICATE_PATH_SPECIFIED = 0xEFFF0057
ISDSC_PATH_COUNT_MISMATCH = 0xEFFF0058
ISDSC_INVALID_PATH_ID = 0xEFFF0059
ISDSC_MULTIPLE_PRIMARY_PATHS_SPECIFIED = 0xEFFF005A
ISDSC_NO_PRIMARY_PATH_SPECIFIED = 0xEFFF005B
ISDSC_DEVICE_ALREADY_PERSISTENTLY_BOUND = 0xEFFF005C
ISDSC_DEVICE_NOT_FOUND = 0xEFFF005D
ISDSC_DEVICE_NOT_ISCSI_OR_PERSISTENT = 0xEFFF005E
ISDSC_DNS_NAME_UNRESOLVED = 0xEFFF005F
ISDSC_NO_CONNECTION_AVAILABLE = 0xEFFF0060
ISDSC_LB_POLICY_NOT_SUPPORTED = 0xEFFF0061
ISDSC_REMOVE_CONNECTION_IN_PROGRESS = 0xEFFF0062
ISDSC_INVALID_CONNECTION_ID = 0xEFFF0063
ISDSC_CANNOT_REMOVE_LEADING_CONNECTION = 0xEFFF0064
ISDSC_RESTRICTED_BY_GROUP_POLICY = 0xEFFF0065
ISDSC_ISNS_FIREWALL_BLOCKED = 0xEFFF0066
ISDSC_FAILURE_TO_PERSIST_LB_POLICY = 0xEFFF0067
ISDSC_INVALID_HOST = 0xEFFF0068

err_msg_dict = {
    ISDSC_NON_SPECIFIC_ERROR: _('A non specific error occurred.'),
    ISDSC_LOGIN_FAILED: _('Login Failed.'),
    ISDSC_CONNECTION_FAILED: _('Connection Failed.'),
    ISDSC_INITIATOR_NODE_ALREADY_EXISTS: _('Initiator Node Already Exists.'),
    ISDSC_INITIATOR_NODE_NOT_FOUND: _('Initiator Node Does Not Exist.'),
    ISDSC_TARGET_MOVED_TEMPORARILY: _('Target Moved Temporarily.'),
    ISDSC_TARGET_MOVED_PERMANENTLY: _('Target Moved Permanently.'),
    ISDSC_INITIATOR_ERROR: _('Initiator Error.'),
    ISDSC_AUTHENTICATION_FAILURE: _('Authentication Failure.'),
    ISDSC_AUTHORIZATION_FAILURE: _('Authorization Failure.'),
    ISDSC_NOT_FOUND: _('Not Found.'),
    ISDSC_TARGET_REMOVED: _('Target Removed.'),
    ISDSC_UNSUPPORTED_VERSION: _('Unsupported Version.'),
    ISDSC_TOO_MANY_CONNECTIONS: _('Too many Connections.'),
    ISDSC_MISSING_PARAMETER: _('Missing Parameter.'),
    ISDSC_CANT_INCLUDE_IN_SESSION: _('Can not include in session.'),
    ISDSC_SESSION_TYPE_NOT_SUPPORTED: _('Session type not supported.'),
    ISDSC_TARGET_ERROR: _('Target Error.'),
    ISDSC_SERVICE_UNAVAILABLE: _('Service Unavailable.'),
    ISDSC_OUT_OF_RESOURCES: _('Out of Resources.'),
    ISDSC_CONNECTION_ALREADY_EXISTS: _('Connections already exist '
                                       'on initiator node.'),
    ISDSC_SESSION_ALREADY_EXISTS: _('Session Already Exists.'),
    ISDSC_INITIATOR_INSTANCE_NOT_FOUND: _('Initiator Instance '
                                          'Does Not Exist.'),
    ISDSC_TARGET_ALREADY_EXISTS: _('Target Already Exists.'),
    ISDSC_DRIVER_BUG: _('The iscsi driver implementation did '
                        'not complete an operation correctly.'),
    ISDSC_INVALID_TEXT_KEY: _('An invalid key text was encountered.'),
    ISDSC_INVALID_SENDTARGETS_TEXT: _('Invalid SendTargets response '
                                      'text was encountered.'),
    ISDSC_INVALID_SESSION_ID: _('Invalid Session Id.'),
    ISDSC_SCSI_REQUEST_FAILED: _('The scsi request failed.'),
    ISDSC_TOO_MANY_SESSIONS: _('Exceeded max sessions for this initiator.'),
    ISDSC_SESSION_BUSY: _('Session is busy since a request '
                          'is already in progress.'),
    ISDSC_TARGET_MAPPING_UNAVAILABLE: _('The target mapping requested '
                                        'is not available.'),
    ISDSC_ADDRESS_TYPE_NOT_SUPPORTED: _('The Target Address type given '
                                        'is not supported.'),
    ISDSC_LOGON_FAILED: _('Logon Failed.'),
    ISDSC_SEND_FAILED: _('TCP Send Failed.'),
    ISDSC_TRANSPORT_ERROR: _('TCP Transport Error'),
    ISDSC_VERSION_MISMATCH: _('iSCSI Version Mismatch'),
    ISDSC_TARGET_MAPPING_OUT_OF_RANGE: _('The Target Mapping Address passed '
                                         'is out of range for the '
                                         'adapter configuration.'),
    ISDSC_TARGET_PRESHAREDKEY_UNAVAILABLE: _('The preshared key for the '
                                             'target or IKE identification '
                                             'payload is not available.'),
    ISDSC_TARGET_AUTHINFO_UNAVAILABLE: _('The authentication information for '
                                         'the target is not available.'),
    ISDSC_TARGET_NOT_FOUND: _('The target name is not found or is '
                              'marked as hidden from login.'),
    ISDSC_LOGIN_USER_INFO_BAD: _('One or more parameters specified in '
                                 'LoginTargetIN structure is invalid.'),
    ISDSC_TARGET_MAPPING_EXISTS: _('Given target mapping already exists.'),
    ISDSC_HBA_SECURITY_CACHE_FULL: _('The HBA security information cache '
                                     'is full.'),
    ISDSC_INVALID_PORT_NUMBER: _('The port number passed is '
                                 'not valid for the initiator.'),
    ISDSC_OPERATION_NOT_ALL_SUCCESS: _('The operation was not successful '
                                       'for all initiators or discovery '
                                       'methods.'),
    ISDSC_HBA_SECURITY_CACHE_NOT_SUPPORTED: _('The HBA security information '
                                              'cache is not supported by '
                                              'this adapter.'),
    ISDSC_IKE_ID_PAYLOAD_TYPE_NOT_SUPPORTED: _('The IKE id payload type '
                                               'specified is not supported.'),
    ISDSC_IKE_ID_PAYLOAD_INCORRECT_SIZE: _('The IKE id payload size '
                                           'specified is not correct.'),
    ISDSC_TARGET_PORTAL_ALREADY_EXISTS: _('Target Portal Structure '
                                          'Already Exists.'),
    ISDSC_TARGET_ADDRESS_ALREADY_EXISTS: _('Target Address Structure '
                                           'Already Exists.'),
    ISDSC_NO_AUTH_INFO_AVAILABLE: _('There is no IKE authentication '
                                    'information available.'),
    ISDSC_NO_TUNNEL_OUTER_MODE_ADDRESS: _('There is no tunnel mode outer '
                                          'address specified.'),
    ISDSC_CACHE_CORRUPTED: _('Authentication or tunnel '
                             'address cache is corrupted.'),
    ISDSC_REQUEST_NOT_SUPPORTED: _('The request or operation '
                                   'is not supported.'),
    ISDSC_TARGET_OUT_OF_RESORCES: _('The target does not have enough '
                                    'resources to process the '
                                    'given request.'),
    ISDSC_SERVICE_DID_NOT_RESPOND: _('The initiator service did '
                                     'not respond to the request '
                                     'sent by the driver.'),
    ISDSC_ISNS_SERVER_NOT_FOUND: _('The Internet Storage Name Server (iSNS) '
                                   'server was not found or is unavailable.'),
    ISDSC_OPERATION_REQUIRES_REBOOT: _('The operation was successful but '
                                       'requires a driver reload or reboot '
                                       'to become effective.'),
    ISDSC_NO_PORTAL_SPECIFIED: _('There is no target portal available '
                                 'to complete the login.'),
    ISDSC_CANT_REMOVE_LAST_CONNECTION: _('Cannot remove the last '
                                         'connection for a session.'),
    ISDSC_SERVICE_NOT_RUNNING: _('The Microsoft iSCSI initiator '
                                 'service has not been started.'),
    ISDSC_TARGET_ALREADY_LOGGED_IN: _('The target has already been '
                                      'logged in via an iSCSI session.'),
    ISDSC_DEVICE_BUSY_ON_SESSION: _('The session cannot be logged out '
                                    'since a device on that session is '
                                    'currently being used.'),
    ISDSC_COULD_NOT_SAVE_PERSISTENT_LOGIN_DATA: _('Failed to save persistent '
                                                  'login information.'),
    ISDSC_COULD_NOT_REMOVE_PERSISTENT_LOGIN_DATA: _('Failed to remove '
                                                    'persistent login '
                                                    'information.'),
    ISDSC_PORTAL_NOT_FOUND: _('The specified portal was not found.'),
    ISDSC_INITIATOR_NOT_FOUND: _('The specified initiator '
                                 'name was not found.'),
    ISDSC_DISCOVERY_MECHANISM_NOT_FOUND: _('The specified discovery '
                                           'mechanism was not found.'),
    ISDSC_IPSEC_NOT_SUPPORTED_ON_OS: _('iSCSI does not support IPSEC '
                                       'for this version of the OS.'),
    ISDSC_PERSISTENT_LOGIN_TIMEOUT: _('The iSCSI service timed out waiting '
                                      'for all persistent logins to '
                                      'complete.'),
    ISDSC_SHORT_CHAP_SECRET: _('The specified CHAP secret is less than '
                               '96 bits and will not be usable for '
                               'authenticating over non ipsec connections.'),
    ISDSC_EVALUATION_PEROID_EXPIRED: _('The evaluation period for the '
                                       'iSCSI initiator service has '
                                       'expired.'),
    ISDSC_INVALID_CHAP_SECRET: _('CHAP secret given does not conform '
                                 'to the standard. Please see system '
                                 'event log for more information.'),
    ISDSC_INVALID_TARGET_CHAP_SECRET:
    _('Target CHAP secret given is invalid. Maximum size of CHAP secret'
      'is 16 bytes. Minimum size is 12 bytes if IPSec is not used.'),
    ISDSC_INVALID_INITIATOR_CHAP_SECRET: _('Initiator CHAP secret given is '
                                           'invalid. Maximum size of CHAP '
                                           'secret is 16 bytes. Minimum size '
                                           'is 12 bytes if IPSec is '
                                           'not used.'),
    ISDSC_INVALID_CHAP_USER_NAME: _('CHAP Username given is invalid.'),
    ISDSC_INVALID_LOGON_AUTH_TYPE: _('Logon Authentication type '
                                     'given is invalid.'),
    ISDSC_INVALID_TARGET_MAPPING: _('Target Mapping information '
                                    'given is invalid.'),
    ISDSC_INVALID_TARGET_ID: _('Target Id given in '
                               'Target Mapping is invalid.'),
    ISDSC_INVALID_ISCSI_NAME: _('The iSCSI name specified contains '
                                'invalid characters or is too long.'),
    ISDSC_INCOMPATIBLE_ISNS_VERSION: _('The version number returned from the '
                                       'Internet Storage Name Server (iSNS) '
                                       'server is not compatible with this '
                                       'version of the iSNS client.'),
    ISDSC_FAILED_TO_CONFIGURE_IPSEC: _('Initiator failed to configure IPSec '
                                       'for the given connection. This could '
                                       'be because of low resources.'),
    ISDSC_BUFFER_TOO_SMALL: _('The buffer given for processing '
                              'the request is too small.'),
    ISDSC_INVALID_LOAD_BALANCE_POLICY: _('The given Load Balance '
                                         'policy is not recognized '
                                         'by iScsi initiator.'),
    ISDSC_INVALID_PARAMETER: _('One or more paramaters '
                               'specified is not valid.'),
    ISDSC_DUPLICATE_PATH_SPECIFIED: _('Duplicate PathIds were '
                                      'specified in the call to '
                                      'set Load Balance Policy.'),
    ISDSC_PATH_COUNT_MISMATCH: _('Number of paths specified in '
                                 'Set Load Balance Policy does not '
                                 'match the number of paths to the target.'),
    ISDSC_INVALID_PATH_ID: _('Path Id specified in the call to '
                             'set Load Balance Policy is not valid'),
    ISDSC_MULTIPLE_PRIMARY_PATHS_SPECIFIED: _('Multiple primary paths '
                                              'specified when only one '
                                              'primary path is expected.'),
    ISDSC_NO_PRIMARY_PATH_SPECIFIED: _('No primary path specified when '
                                       'at least one is expected.'),
    ISDSC_DEVICE_ALREADY_PERSISTENTLY_BOUND: _('Device is already a '
                                               'persistently bound device.'),
    ISDSC_DEVICE_NOT_FOUND: _('Device was not found.'),
    ISDSC_DEVICE_NOT_ISCSI_OR_PERSISTENT: _('The device specified does not '
                                            'originate from an iSCSI disk '
                                            'or a persistent iSCSI login.'),
    ISDSC_DNS_NAME_UNRESOLVED: _('The DNS name specified was not resolved.'),
    ISDSC_NO_CONNECTION_AVAILABLE: _('There is no connection available '
                                     'in the iSCSI session to '
                                     'process the request.'),
    ISDSC_LB_POLICY_NOT_SUPPORTED: _('The given Load Balance '
                                     'policy is not supported.'),
    ISDSC_REMOVE_CONNECTION_IN_PROGRESS: _('A remove connection request '
                                           'is already in progress for '
                                           'this session.'),
    ISDSC_INVALID_CONNECTION_ID: _('Given connection was not '
                                   'found in the session.'),
    ISDSC_CANNOT_REMOVE_LEADING_CONNECTION: _('The leading connection in '
                                              'the session cannot be '
                                              'removed.'),
    ISDSC_RESTRICTED_BY_GROUP_POLICY: _('The operation cannot be performed '
                                        'since it does not conform with '
                                        'the group policy assigned to '
                                        'this computer.'),
    ISDSC_ISNS_FIREWALL_BLOCKED: _('The operation cannot be performed since '
                                   'the Internet Storage Name Server '
                                   '(iSNS) firewall exception has '
                                   'not been enabled.'),
    ISDSC_FAILURE_TO_PERSIST_LB_POLICY: _('Failed to persist load '
                                          'balancing policy parameters.'),
    ISDSC_INVALID_HOST: _('The name could not be resolved to an IP Address.'),
}
