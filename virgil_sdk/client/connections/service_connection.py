# Copyright (C) 2016-2018 Virgil Security Inc.
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

from virgil_sdk.client import ClientException, UnauthorizedClientException
from .base_connection import BaseConnection
from .urllib import urllib2
from .urllib import RequestWithMethod


class ServiceConnection(BaseConnection):

    def __init__(self, base_url):
        self.__base_url = base_url

    def send(self, request):
        prepared_request = self._prepare_request(request)
        ctx = ssl.create_default_context()
        try:
            response = urllib2.urlopen(prepared_request, context=ctx)
            result = response.read()
            return json.loads(result.decode()), dict(response.getheaders())
        except urllib2.HTTPError as exception:
            client_errors = {
                400: "Request Error",
                401: "Authorization Error",
                404: "Entity Not Found",
                405: "Method Not Allowed",
                500: "Internal Server Error"
            }
            try:
                error_res = exception.read()
                error_body = json.loads(error_res.decode())
                if isinstance(error_body, dict) and "message" in error_body.keys() and "code" in error_body.keys():
                    raise ClientException(error_body["message"], error_body["code"]) from None
                if exception.code in client_errors.keys():
                    if exception.code == 401:
                        raise UnauthorizedClientException(client_errors[exception.code], exception.code) from None
                    raise ClientException(client_errors[exception.code], exception.code) from None
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
        prepared_request = RequestWithMethod(
            url,
            method=request.method,
            data=data,
            headers=headers
        )
        return prepared_request

    @property
    def base_url(self):
        return self.__base_url
