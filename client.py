#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
FDSN Web service client for BATS.
:copyright:
    The BATS Development Team (dmc@earth.sinica.edu.tw)
"""
import copy
import gzip
import io
import os
import re
from socket import timeout as socket_timeout
import textwrap
import threading
import warnings
from collections import OrderedDict
from urllib.parse import urlparse

from lxml import etree

import obspy
from obspy import UTCDateTime, read_inventory
from obspy.core.compatibility import collections_abc

from header import (DEFAULT_PARAMETERS, DEFAULT_USER_AGENT, BATSWS, OPTIONAL_PARAMETERS,
                     URL_DEFAULT_SUBPATH, URL_MAPPINGS, DEFAULT_SERVICES,
                     FDSNException, FDSNRedirectException, FDSNNoDataException,
                     FDSNTimeoutException,
                     FDSNNoAuthenticationServiceException,
                     FDSNBadRequestException, FDSNNoServiceException,
                     FDSNInternalServerException, FDSNTooManyRequestsException,
                     FDSNRequestTooLargeException,
                     FDSNServiceUnavailableException,
                     FDSNUnauthorizedException,
                     FDSNForbiddenException,
                     FDSNDoubleAuthenticationException,
                     FDSNInvalidRequestException)

# from .wadl_parser import WADLParser

from urllib.parse import urlencode
import urllib.request as urllib_request
import urllib.error as urllib_error
import queue
import json
import hashlib

# https://tecws1.earth.sinica.edu.tw/BATSWS/query?type=ms&tb=2009-06-06T06:00:00&te=2009-06-06T06:10:00&sta=CHGB&ch=BH?&l=&account=chute&password=0e8ff133328ef72d60aae59482c1749f
# http://tecws1.earth.sinica.edu.tw/BATSWS/query?tb=2008-04-16T00:00:00&account=chute&password=0e8ff133328ef72d60aae59482c1749f&te=2008-04-16T01:00:00&sta=CHGB&ch=*
# https://tecws1.earth.sinica.edu.tw/BATSWS/respquery?type=simple&tb=2009-06-06&te=2009-06-06&sta=CHGB&ch=BH?&dl=1
class Client(object):
    """
    FDSN Web service request client.
    """

    RE_UINT8 = r'(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})'
    RE_HEX4 = r'(?:[\d,a-f]{4}|[1-9,a-f][0-9,a-f]{0,2}|0)'

    RE_IPv4 = r'(?:' + RE_UINT8 + r'(?:\.' + RE_UINT8 + r'){3})'
    RE_IPv6 = \
        r'(?:\[' + RE_HEX4 + r'(?::' + RE_HEX4 + r'){7}\]' + \
        r'|\[(?:' + RE_HEX4 + r':){0,5}' + RE_HEX4 + r'::\]' + \
        r'|\[::' + RE_HEX4 + r'(?::' + RE_HEX4 + r'){0,5}\]' + \
        r'|\[::' + RE_HEX4 + r'(?::' + RE_HEX4 + r'){0,3}:' + RE_IPv4 + \
        r'\]' + \
        r'|\[' + RE_HEX4 + r':' + \
        r'(?:' + RE_HEX4 + r':|:' + RE_HEX4 + r'){0,4}' + \
        r':' + RE_HEX4 + r'\])'

    URL_REGEX = r'https?://' + \
                r'(' + RE_IPv4 + \
                r'|' + RE_IPv6 + \
                r'|localhost' + \
                r'|\w+' + \
                r'|(?:\w(?:[\w-]{0,61}[\w])?\.){1,}([a-z]{2,6}))' + \
                r'(?::\d{2,5})?' + \
                r'(/[\w\.-]+)*/?$'

    @classmethod
    def _validate_base_url(cls, base_url):
        if re.match(cls.URL_REGEX, base_url, re.IGNORECASE):
            return True
        else:
            return False

    def __init__(self, base_url="BATS", user=None, password=None,
                 user_agent=DEFAULT_USER_AGENT, debug=False,
                 timeout=120):
        """
        Initializes an FDSN Web Service client.
        >>> client = Client("BATS")
        >>> print(client)  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
        FDSN Webservice Client (base url: https://BATS.earth.sinica.edu.tw)
        Available Services: 'dataselect' (v...), 'station' (v...),
        Use e.g. client.help('dataselect') for the
        parameter description of the individual services
        or client.help() for parameter description of
        all webservices.
        :type base_url: str
        :param base_url: Base URL of FDSN web service compatible server
            (e.g. "https://BATS.earth.sinica.edu.tw") or key string for recognized
            server (one of %s).
        :type user: str
        :param user: User name of JSON Web Tokens Authentication for access to
            restricted data.
        :type password: str
        :param password: Password of JSON Web Tokens Authentication for access to
            restricted data.
        :type user_agent: str
        :param user_agent: The user agent for all requests.
        :type debug: bool
        :param debug: Debug flag.
        :type timeout: float
        :param timeout: Maximum time (in seconds) to wait for a single request
            to receive the first byte of the response (after which an exception
            is raised).
        """
        self.debug = debug
        self.user = user
        self.password = password
        self.timeout = timeout

        if base_url.upper() in URL_MAPPINGS:
            url_mapping = base_url.upper()
            base_url = URL_MAPPINGS[url_mapping]
            url_subpath = URL_DEFAULT_SUBPATH
        else:
            if base_url.isalpha():
                msg = "The FDSN service shortcut `{}` is unknown."\
                      .format(base_url)
                raise ValueError(msg)
            url_subpath = URL_DEFAULT_SUBPATH

        # Make sure the base_url does not end with a slash.
        base_url = base_url.strip("/")
        # Catch invalid URLs to avoid confusing error messages
        if not self._validate_base_url(base_url):
            msg = "The FDSN service base URL `{}` is not a valid URL."\
                  .format(base_url)
            raise ValueError(msg)

        self.base_url = base_url
        self.url_subpath = url_subpath

        self._set_opener()

        self.request_headers = {"User-Agent": user_agent}

        if self.debug is True:
            print("Base URL: %s" % self.base_url)
            print("Request Headers: %s" % str(self.request_headers))

        self.services = DEFAULT_SERVICES

    def set_credentials(self, user, password):
        """
        Set user and password resulting in subsequent web service
        requests for waveforms being authenticated for potential access to
        restricted data.
        This will overwrite any previously set-up credentials/authentication.
        :type user: str
        :param user: User name of credentials.
        :type password: str
        :param password: Password for given user name.
        """
        self.user = user
        self.password = hashlib.md5(password.encode())

    def _set_opener(self):
        # Only add the authentication handler if required.
        handlers = []
        # Don't install globally to not mess with other codes.
        self._url_opener = urllib_request.build_opener(*handlers)
        if self.debug:
            print('Installed new opener with handlers: {!s}'.format(handlers))

    def get_stations(self, starttime=None, endtime=None, startbefore=None,
                        startafter=None, endbefore=None, endafter=None,
                        network=None, station=None, location=None, channel=None,
                        minlatitude=None, maxlatitude=None, minlongitude=None,
                        maxlongitude=None, latitude=None, longitude=None,
                        minradius=None, maxradius=None, level=None,
                        includerestricted=None, includeavailability=None,
                        updatedafter=None, matchtimeseries=None, filename=None,
                        format=None, **kwargs):

        if "station" not in self.services:
            msg = "The current client does not have a station service."
            raise ValueError(msg)

        locs = locals()

        setup_query_dict('station', locs, kwargs)

        url = self._create_url_from_parameters(
            "station", DEFAULT_PARAMETERS['station'], kwargs)
        data_stream = self._download(url)
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
        else:
            # This works with XML and StationXML data.
            inventory = read_inventory(data_stream)
            data_stream.close()
            return inventory

    def get_waveforms(self, sta, ch, tb, te, type, filename=None, **kwargs):
        """
        Query the qeury service of the client.
        """
        if "query" not in self.services:
            msg = "The current client does not have a query service."
            raise ValueError(msg)

        locs = locals()
        setup_query_dict('query', locs, kwargs)

        url = self._create_url_from_parameters(
            "query", DEFAULT_PARAMETERS['query'], kwargs)
        # Gzip not worth it for MiniSEED and most likely disabled for this
        # route in any case.
        data_stream = self._download(url, use_gzip=False)
        data_stream.seek(0, 0)
        if filename:
            self._write_to_file_object(filename, data_stream)
            data_stream.close()
        else:
            st = obspy.read(data_stream, format="MSEED")
            data_stream.close()
            st.trim(tb, te)
            return st

    def __str__(self):
        services_string = ["'%s'" % (s)
                            for s in BATSWS if s in self.services]
        other_services = sorted([s for s in self.services if s not in BATSWS])
        services_string += ["'%s'" % s for s in other_services]
        services_string = ", ".join(services_string)
        ret = ("FDSN Webservice Client (base url: {url})\n"
                "Available Services: {services}\n\n"
                .format(url=self.base_url, services=services_string))
        return ret

    def _write_to_file_object(self, filename_or_object, data_stream):
        if hasattr(filename_or_object, "write"):
            filename_or_object.write(data_stream.read())
            return
        with open(filename_or_object, "wb") as fh:
            fh.write(data_stream.read())

    def _create_url_from_parameters(self, service, default_params, parameters):
        """
        """
        service_params = self.services[service]
        # Get all required parameters and make sure they are available!
        required_parameters = [
            key for key, value in service_params.items()
            if value["required"] is True]
        for req_param in required_parameters:
            if req_param not in parameters:
                msg = "Parameter '%s' is required." % req_param
                raise TypeError(msg)

        final_parameter_set = {}

        # Now loop over all parameters, convert them and make sure they are
        # accepted by the service.
        for key, value in parameters.items():
            if key not in service_params:
                # If it is not in the service but in the default parameters
                # raise a warning.
                if key in default_params:
                    msg = ("The standard parameter '%s' is not supported by "
                           "the webservice. It will be silently ignored." %
                           key)
                    warnings.warn(msg)
                    continue
                # Otherwise raise an error.
                else:
                    msg = \
                        "The parameter '%s' is not supported by the service." \
                        % key
                    raise TypeError(msg)
            # Now attempt to convert the parameter to the correct type.
            this_type = service_params[key]["type"]

            # Try to decode to be able to work with bytes.
            if this_type is str:
                try:
                    value = value.decode()
                except AttributeError:
                    pass

            try:
                value = this_type(value)
            except Exception:
                msg = "'%s' could not be converted to type '%s'." % (
                    str(value), this_type.__name__)
                raise TypeError(msg)
            # Now convert to a string that is accepted by the webservice.
            value = convert_to_string(value)
            final_parameter_set[key] = value

            # Pass username and password
            final_parameter_set['account'] = self.user
            if self.password != None:
                final_parameter_set['password'] = self.password.hexdigest()
            else:
                final_parameter_set['password'] = self.password

        return self._build_url(service, parameters=final_parameter_set)

    def _download(self, url, return_string=False, data=None, use_gzip=True, use_jwt=None):
        code, data = download_url(
            url, opener=self._url_opener, headers=self.request_headers,
            debug=self.debug, return_string=return_string, data=data,
            timeout=self.timeout, use_gzip=use_gzip, use_jwt=use_jwt)
        raise_on_error(code, data)
        return data

    def _build_url(self, service, parameters={}):
        """
        Builds the correct URL.
        """
        return build_url(self.base_url, service, parameters,
                         subpath=self.url_subpath)

def convert_to_string(value):
    """
    Takes any value and converts it to a string compliant with the FDSN
    webservices.
    Will raise a ValueError if the value could not be converted.
    >>> print(convert_to_string("abcd"))
    abcd
    >>> print(convert_to_string(1))
    1
    >>> print(convert_to_string(1.2))
    1.2
    >>> print(convert_to_string( \
              UTCDateTime(2012, 1, 2, 3, 4, 5, 666666)))
    2012-01-02T03:04:05.666666
    >>> print(convert_to_string(True))
    true
    >>> print(convert_to_string(False))
    false
    """
    if isinstance(value, str):
        return value
    # Boolean test must come before integer check!
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, int):
        return str(value)
    elif isinstance(value, float):
        return str(value)
    elif isinstance(value, UTCDateTime):
        return str(value).replace("Z", "")
    else:
        raise TypeError("Unexpected type %s" % repr(value))

def build_url(base_url, service, parameters=None, subpath='BATSWS'):
    """
    URL builder for the FDSN webservices.
    Built as a separate function to enhance testability.
    >>> print(build_url("http://service.iris.edu", "dataselect", 1, \
                        "application.wadl"))
    http://service.iris.edu/BATSWS/dataselect/1/application.wadl
    >>> print(build_url("http://service.iris.edu", "dataselect", 1, \
                        "query", {"cha": "EHE"}))
    http://service.iris.edu/BATSWS/dataselect/1/query?cha=EHE
    """
    # Avoid mutable kwargs.
    if parameters is None:
        parameters = {}

    # Only allow certain resource types.
    if service not in ["query", "respquery"]:
        msg = "Resource type '%s' not allowed. Allowed types: \n%s" % \
            (service, ",".join(("query", "respquery")))
        raise ValueError(msg)

    # Apply per-service mappings if any.:
    parts = (base_url, subpath.lstrip('/'), service)
    url = "/".join(parts)

    if parameters:
        # Strip parameters.
        for key, value in parameters.items():
            try:
                parameters[key] = value.strip()
            except Exception:
                pass
        url = "?".join((url, urlencode(parameters, safe=':,*?')))
        
    return url

def raise_on_error(code, data):
    """
    Raise an error for non-200 HTTP response codes
    :type code: int
    :param code: HTTP response code
    :type data: :class:`io.BytesIO`
    :param data: Data returned by the server
    """
    # get detailed server response message
    if code != 200:
        try:
            server_info = data.read()
        except Exception:
            server_info = None
        else:
            server_info = server_info.decode('ASCII', errors='ignore')
        if server_info:
            server_info = "\n".join(
                line for line in server_info.splitlines() if line)
    
    # BATSWS auth failed
    if code == 200:
        try:
            server_info = data.read()
            server_info_len = len(server_info)
            # The smallest possible mini-SEED record is made up of 128 bytes.
            if server_info_len < 128:
                # b'\xef\xbb\xbfAuthentication failed!' -> Authentication failed!
                server_info = server_info.decode("utf-8")
                # The leading letter is strange, remove it.
                server_info = server_info[1:] 
                if server_info == 'Authentication failed!':
                    raise Exception
        except Exception:
            raise FDSNUnauthorizedException("Unauthorized, authentication "
                                        "required.", server_info)

    # No data.
    if code == 204:
        raise FDSNNoDataException("No data available for request.",
                                  server_info)
    elif code == 400:
        msg = ("Bad request. If you think your request was valid "
               "please contact the developers.")
        raise FDSNBadRequestException(msg, server_info)
    elif code == 401:
        raise FDSNUnauthorizedException("Unauthorized, authentication "
                                        "required.", server_info)
    elif code == 403:
        raise FDSNForbiddenException("Authentication failed.",
                                     server_info)
    elif code == 413:
        raise FDSNRequestTooLargeException("Request would result in too much "
                                           "data. Denied by the datacenter. "
                                           "Split the request in smaller "
                                           "parts", server_info)
    # Request URI too large.
    elif code == 414:
        msg = ("The request URI is too large. Please contact the ObsPy "
               "developers.", server_info)
        raise NotImplementedError(msg)
    elif code == 429:
        msg = ("Sent too many requests in a given amount of time ('rate "
               "limiting'). Wait before making a new request.", server_info)
        raise FDSNTooManyRequestsException(msg, server_info)
    elif code == 500:
        raise FDSNInternalServerException("Service responds: Internal server "
                                          "error", server_info)
    elif code == 503:
        raise FDSNServiceUnavailableException("Service temporarily "
                                              "unavailable",
                                              server_info)
    elif code is None:
        if "timeout" in str(data).lower() or "timed out" in str(data).lower():
            raise FDSNTimeoutException("Timed Out")
        else:
            raise FDSNException("Unknown Error (%s): %s" % (
                (str(data.__class__.__name__), str(data))))
    # Catch any non 200 codes.
    elif code != 200:
        raise FDSNException("Unknown HTTP code: %i" % code, server_info)

def download_url(url, opener, timeout=10, headers={}, debug=False,
                 return_string=True, data=None, use_gzip=True, use_jwt=None):
    """
    Returns a pair of tuples.
    The first one is the returned HTTP code and the second the data as
    string.
    Will return a tuple of Nones if the service could not be found.
    All encountered exceptions will get raised unless `debug=True` is
    specified.
    Performs a http GET if data=None, otherwise a http POST.
    """
    if debug is True:
        print("Downloading %s %s requesting gzip compression" % (
            url, "with" if use_gzip else "without"))
        if data:
            print("Sending along the following payload:")
            print("-" * 70)
            print(data.decode())
            print("-" * 70)

    try:
        request = urllib_request.Request(url=url, headers=headers)
        # Request gzip encoding if desired.
        if use_gzip:
            request.add_header("Accept-encoding", "gzip")
        if use_jwt:
            request.add_header("accept", "application/json")
            request.add_header("Authorization", f'JWT {use_jwt}')

        url_obj = opener.open(request, timeout=timeout, data=data)
    # Catch HTTP errors.
    except urllib_request.HTTPError as e:
        if debug is True:
            msg = "HTTP error %i, reason %s, while downloading '%s': %s" % \
                  (e.code, str(e.reason), url, e.read())
            print(msg)
        return e.code, e
    except Exception as e:
        if debug is True:
            print("Error while downloading: %s" % url)
        return None, e

    code = url_obj.getcode()

    # Unpack gzip if necessary.
    if url_obj.info().get("Content-Encoding") == "gzip":
        if debug is True:
            print("Uncompressing gzipped response for %s" % url)
        # Cannot directly stream to gzip from urllib!
        # http://www.enricozini.org/2011/cazzeggio/python-gzip/
        buf = io.BytesIO(url_obj.read())
        buf.seek(0, 0)
        f = gzip.GzipFile(fileobj=buf)
    else:
        f = url_obj

    if return_string is False:
        data = io.BytesIO(f.read())
    else:
        data = f.read()

    if debug is True:
        print("Downloaded %s with HTTP code: %i" % (url, code))

    return code, data

def setup_query_dict(service, locs, kwargs):
    """
    """
    # short aliases are not mentioned in the downloaded WADLs, so we have
    # to map it here according to the official FDSN WS documentation
    for key in list(kwargs.keys()):
        value = kwargs.pop(key)
        if value is not None:
            kwargs[key] = value

    for param in DEFAULT_PARAMETERS[service] + OPTIONAL_PARAMETERS[service]:
        value = locs[param]
        if value is not None:
            kwargs[param] = value
