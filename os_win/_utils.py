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

import netaddr
import six
import socket
import time
import types

from oslo_concurrency import lockutils
from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import reflection

from os_win._i18n import _LE

LOG = logging.getLogger(__name__)


synchronized = lockutils.synchronized_with_prefix('oswin-')


def execute(*cmd, **kwargs):
    """Convenience wrapper around oslo's execute() method."""
    return processutils.execute(*cmd, **kwargs)


def parse_server_string(server_str):
    """Parses the given server_string and returns a tuple of host and port.
    If it's not a combination of host part and port, the port element
    is an empty string. If the input is invalid expression, return a tuple of
    two empty strings.
    """
    try:
        # First of all, exclude pure IPv6 address (w/o port).
        if netaddr.valid_ipv6(server_str):
            return (server_str, '')

        # Next, check if this is IPv6 address with a port number combination.
        if server_str.find("]:") != -1:
            (address, port) = server_str.replace('[', '', 1).split(']:')
            return (address, port)

        # Third, check if this is a combination of an address and a port
        if server_str.find(':') == -1:
            return (server_str, '')

        # This must be a combination of an address and a port
        (address, port) = server_str.split(':')
        return (address, port)

    except (ValueError, netaddr.AddrFormatError):
        LOG.error(_LE('Invalid server_string: %s'), server_str)
        return ('', '')


def get_wrapped_function(function):
    """Get the method at the bottom of a stack of decorators."""
    if not hasattr(function, '__closure__') or not function.__closure__:
        return function

    def _get_wrapped_function(function):
        if not hasattr(function, '__closure__') or not function.__closure__:
            return None

        for closure in function.__closure__:
            func = closure.cell_contents

            deeper_func = _get_wrapped_function(func)
            if deeper_func:
                return deeper_func
            elif isinstance(closure.cell_contents, types.FunctionType):
                return closure.cell_contents

    return _get_wrapped_function(function)


def retry_decorator(max_retry_count=5, inc_sleep_time=1,
                    max_sleep_time=1, exceptions=(), error_codes=()):
    if isinstance(error_codes, six.integer_types):
        error_codes = (error_codes, )

    def wrapper(f):
        def inner(*args, **kwargs):
            try_count = 0
            sleep_time = 0

            while True:
                try:
                    return f(*args, **kwargs)
                except exceptions as exc:
                    with excutils.save_and_reraise_exception() as ctxt:
                        err_code = getattr(exc, 'error_code', None)
                        expected_err_code = (err_code in error_codes
                                             or not error_codes)
                        should_retry = (expected_err_code
                                        and try_count < max_retry_count)
                        ctxt.reraise = not should_retry

                        if should_retry:
                            try_count += 1
                            func_name = reflection.get_callable_name(f)
                            LOG.debug("Got expected exception %(exc)s while "
                                      "calling function %(func_name)s. "
                                      "Retries left: %(retries_left)d. "
                                      "Retrying in %(sleep_time)s seconds.",
                                      dict(exc=exc,
                                           func_name=func_name,
                                           retries_left=(
                                               max_retry_count - try_count),
                                           sleep_time=sleep_time))

                            sleep_time = min(sleep_time + inc_sleep_time,
                                             max_sleep_time)
                            time.sleep(sleep_time)
        return inner
    return wrapper


def get_ips(addr):
    addr_info = socket.getaddrinfo(addr, None, 0, 0, 0)
    # Returns IPv4 and IPv6 addresses, ordered by protocol family
    addr_info.sort()
    return [a[4][0] for a in addr_info]
