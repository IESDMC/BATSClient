# -*- coding: utf-8 -*-
"""
FDSN Web service client for BATS.
:copyright:
    The BATS Development Team (dmc@earth.sinica.edu.tw)
"""
import platform
import sys

from obspy import UTCDateTime

class FDSNException(Exception):
    status_code = None

    def __init__(self, value, server_info=None):
        if server_info is not None:
            if self.status_code is None:
                value = "\n".join([value, "Detailed response of server:", "",
                                   server_info])
            else:
                value = "\n".join([value,
                                   "HTTP Status code: {}"
                                   .format(self.status_code),
                                   "Detailed response of server:",
                                   "",
                                   server_info])
        super(FDSNException, self).__init__(value)


class FDSNNoDataException(FDSNException):
    status_code = 204


class FDSNBadRequestException(FDSNException):
    status_code = 400


class FDSNUnauthorizedException(FDSNException):
    status_code = 401


class FDSNForbiddenException(FDSNException):
    status_code = 403


class FDSNRequestTooLargeException(FDSNException):
    status_code = 413


class FDSNTooManyRequestsException(FDSNException):
    status_code = 429


class FDSNInternalServerException(FDSNException):
    status_code = 500


class FDSNServiceUnavailableException(FDSNException):
    status_code = 503


class FDSNTimeoutException(FDSNException):
    pass


class FDSNRedirectException(FDSNException):
    pass


class FDSNNoAuthenticationServiceException(FDSNException):
    pass


class FDSNDoubleAuthenticationException(FDSNException):
    pass


class FDSNInvalidRequestException(FDSNException):
    pass


class FDSNNoServiceException(FDSNException):
    pass

# https://www.fdsn.org/webservices/datacenters/
URL_MAPPINGS = {
    "BATS": "http://tecws1.earth.sinica.edu.tw/BATSWS",
    "IES": "http://tecws1.earth.sinica.edu.tw/IESWS",
    }

URL_DEFAULT_SUBPATH = ''

BATSWS = ("query", "respquery")

encoding = sys.getdefaultencoding() or "UTF-8"
platform_ = platform.platform().encode(encoding).decode("ascii", "ignore")
# The default User Agent that will be sent with every request.
DEFAULT_USER_AGENT = "BATSClient/ (%s, Python %s)" % (
    platform_, platform.python_version())

DEFAULT_QUERY_PARAMETERS = [
    "tb", "te", "sta", "ch"]

OPTIONAL_QUERY_PARAMETERS = ["type"]

DEFAULT_RESPQUERY_PARAMETERS = [
    "tb", "te", "sta", "ch"]

OPTIONAL_RESPQUERY_PARAMETERS = ["type"]

DEFAULT_PARAMETERS = {
    "query": DEFAULT_QUERY_PARAMETERS,
    "respquery": DEFAULT_RESPQUERY_PARAMETERS}

OPTIONAL_PARAMETERS = {
    "query": OPTIONAL_QUERY_PARAMETERS,
    "respquery": OPTIONAL_RESPQUERY_PARAMETERS}

# The default types if none are given. If the parameter can not be found in
# here and has no specified type, the type will be assumed to be a string.
DEFAULT_TYPES = {
    "tb": UTCDateTime,
    "te": UTCDateTime,
    "sta": str,
    "ch": str,
    "type": str,}

DEFAULT_VALUES = {
    "tb": None,
    "te": None,
    "sta": None,
    "ch": None,
    "type": None,}

DEFAULT_SERVICES = {}
for service in ["query", "respquery"]:
    DEFAULT_SERVICES[service] = {}

    for default_param in DEFAULT_PARAMETERS[service]:
        DEFAULT_SERVICES[service][default_param] = {
            "default_value": DEFAULT_VALUES[default_param],
            "type": DEFAULT_TYPES[default_param],
            "required": False,
        }

    for optional_param in OPTIONAL_PARAMETERS[service]:
        if optional_param == "type":
            if service == "query":
                default_val = "ms"
            else:
                default_val = "simple"
        else:
            default_val = DEFAULT_VALUES[optional_param]

        DEFAULT_SERVICES[service][optional_param] = {
            "default_value": default_val,
            "type": DEFAULT_TYPES[optional_param],
            "required": False,
        }