# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
import json
import ssl
from virgil_sdk.client.http.urllib import urllib2
from virgil_sdk.client.http.urllib import RequestWithMethod

class BaseConnection(object):
    """Base API service connection class."""

    ACCESS_TOKEN_HEADER_NAME = "Authorization"
    """Authorization http header name."""

    def __init__(self, access_token, base_url):
        # type: (str, str) -> None
        """Constructs new BaseConnection object."""
        self.access_token = access_token
        self.base_url = base_url
        self._errors = {}

    def send_request(self, request):
        # type (Request) -> object
        """Sends http request to the endpoint.

        Args:
            request: http.Request object containing sending request data.

        Returns:
            Deserialized python object from the json response.

        Raises:
            HTTPError with error message decoded from errors dictionary.
        """
        prepared_request = self._prepare_request(request)
        ctx = ssl.create_default_context()
        try:
            response = urllib2.urlopen(prepared_request, context=ctx)
            result = response.read()
            return json.loads(result.decode())
        except urllib2.HTTPError as exception:
            try:
                error_res = exception.read()
                error_body = json.loads(error_res.decode())
                error_code = error_body['code'] or error_body['error']['code']
                exception.msg = self._errors[error_code]
                raise
            except ValueError:
                raise exception

    def _prepare_request(self, request):
        # type (http.Request) -> urllib.RequestWithMethod
        """Converts http request to urllib-compatible request.

        Args:
            request: http.Request object containing sending request data.

        Returns:
            urllib-compatible request object.
        """
        url = self.base_url + request.endpoint
        data = request.body
        if data:
            data = json.dumps(data).encode()
        headers = request.headers or {}
        if self.access_token:
            headers[self.ACCESS_TOKEN_HEADER_NAME] = "VIRGIL %s" % self.access_token
        prepared_request = RequestWithMethod(
            url,
            method=request.method,
            data=data,
            headers=headers
        )
        return prepared_request
