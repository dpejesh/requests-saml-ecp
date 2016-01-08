# Copyright (c) 2016 David Shane Holden. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import requests
from lxml import etree
from requests.auth import AuthBase


class XPath(object):
    NAMESPACES = {
        'ECP': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'PAOS': 'urn:liberty:paos:2003-08'
    }

    ASSERTION_CONSUMER_SERVICE_URL = "/S:Envelope/S:Header/ECP:Response/@AssertionConsumerServiceURL"
    HEADER = "/S:Envelope/S:Header"
    RELAY_STATE = "//ECP:RelayState"
    RESPONSE_CONSUMER_URL = "/S:Envelope/S:Header/PAOS:Request/@responseConsumerURL"

    @staticmethod
    def locate(xml, xpath):
        return xml.xpath(xpath, namespaces=XPath.NAMESPACES)[0]


class SAMLECPAuth(AuthBase):
    # Headers required for authentication to IdP
    _idp_request_headers = {
        'Accept': '*/*',
        'Content-Type': 'text/html; charset=utf-8'
    }

    # Headers required for assertion to SP
    _sp_assert_headers = {
        'Content-Type': 'application/vnd.paos+xml'
    }

    # Headers required for requests to the SP to get ECP SOAP messages
    _sp_request_headers = {
        'Accept': 'application/vnd.paos+xml',
        'PAOS': 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'
    }

    _error_urls = "response consumer url ({0}) does not match assertion consumer url ({1})"

    def __init__(self, idp_endpoint, idp_auth):
        self._idp_endpoint = idp_endpoint
        self._idp_auth = idp_auth
        self._cookies = {}

    def handle_response(self, response, **kwargs):
        # If the response content-type is application/vnd.paos+xml then attept
        # to authenticate with the IdP.
        if ("Content-Type" in response.headers) and (response.headers['Content-Type'] == self._sp_request_headers['Accept']):
            envelope = etree.XML(response.content)
            relay_state = XPath.locate(envelope, XPath.RELAY_STATE)
            response_consumer_url = XPath.locate(envelope, XPath.RESPONSE_CONSUMER_URL)

            # Strip the header off the SP response and send it to
            # the IdP.
            header = XPath.locate(envelope, XPath.HEADER)
            header.getparent().remove(header)
            data = etree.tostring(envelope)
            r = requests.post(self._idp_endpoint,
                              allow_redirects=False,
                              auth=self._idp_auth,
                              headers=self._idp_request_headers,
                              data=data,
                              **kwargs)

            envelope = etree.XML(r.content)
            assertion_consumer_service_url = XPath.locate(envelope, XPath.ASSERTION_CONSUMER_SERVICE_URL)

            if response_consumer_url != assertion_consumer_service_url:
                raise Exception(self._error_urls.format(response_consumer_url,
                                                        assertion_consumer_service_url))

            # Replace the IdP SOAP response header with the relay state and
            # send that to the SP.
            header = XPath.locate(envelope, XPath.HEADER)
            header.clear()
            header.append(relay_state)
            data = etree.tostring(envelope)
            r = requests.post(assertion_consumer_service_url,
                              allow_redirects=False,
                              headers=self._sp_assert_headers,
                              data=data,
                              **kwargs)

            # Extract the cookies and save them for reuse.
            self._cookies = r.cookies

            # Recreate the original request and send that to the SP with the
            # new cookies and return that.
            request = response.request.copy()
            request.prepare_cookies(self._cookies)
            response = response.connection.send(request, **kwargs)
            response.history.append(response)
            response.request = request
        return response

    def __call__(self, request, **kwargs):
        request.register_hook("response", self.handle_response)

        # Set the request cookies if any have been saved to prevent
        # authentication with the IdP on every request.
        request.prepare_cookies(self._cookies)

        # Inject the ECP headers into the request.  Without these the SP will
        # not send back an ECP SOAP message if authentication is required.
        request.headers.update(self._sp_request_headers)

        return request
