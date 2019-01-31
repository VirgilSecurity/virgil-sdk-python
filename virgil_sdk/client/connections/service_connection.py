# Copyright (C) 2016-2019 Virgil Security Inc.
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
import ssl
from virgil_sdk.utils import Utils

from virgil_sdk.client import ClientException, UnauthorizedClientException, ExpiredAuthorizationClientException
from .base_connection import BaseConnection
from .urllib import urllib2
from .urllib import RequestWithMethod


class ServiceConnection(BaseConnection):

    def __init__(self, base_url, adapters=None):
        # type: (str, List[HttpRequestAdapter])->None
        self.__base_url = base_url
        self.__adapters = adapters

    def send(self, request):
        # type: (Request) -> Tuple[dict, dict]
        """
        Sends an HTTP request to the API.

        Args:
            request: The HTTP request details.

        Returns:
            Response.

        Raises:
            ClientException: Gets some connection or api errors.
            UnauthorizedClientException: Request without or wrong access token.
        """
        prepared_request = self._prepare_request(request)

        if self.__adapters:
            for adapter in self.__adapters:
                prepared_request = adapter.adapt(prepared_request)

        ctx = ssl.create_default_context()
        try:
            response = urllib2.urlopen(prepared_request, context=ctx)
            result = response.read()
            headers = dict()
            for k, v in dict(response.info()).items():
                headers.update({k.upper(): v})
            return Utils.json_loads(result.decode()), headers
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
                if error_res:
                    error_body = Utils.json_loads(bytes(error_res))
                else:
                    error_body = error_res
                if isinstance(error_body, dict) and "message" in error_body.keys() and "code" in error_body.keys():
                    if exception.code in client_errors.keys() and exception.code == 401:
                        if int(error_body["code"]) == 20304:
                            Utils.raise_from(
                                ExpiredAuthorizationClientException(client_errors[exception.code], exception.code)
                            )
                        Utils.raise_from(UnauthorizedClientException(client_errors[exception.code], exception.code))
                    Utils.raise_from(ClientException(error_body["message"], error_body["code"]))
                else:
                    Utils.raise_from(ClientException(client_errors[exception.code], exception.code))
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
            data = Utils.json_dumps(data).encode()
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
        """
        Gets api url.
        """
        return self.__base_url
