import json
import ssl
from virgil_sdk.client.http.urllib import urllib2
from virgil_sdk.client.http.urllib import RequestWithMethod

class BaseConnection(object):
    ACCESS_TOKEN_HEADER_NAME = "Authorization"

    def __init__(self, access_token, base_url):
        self.access_token = access_token
        self.base_url = base_url
        self._errors = {}

    def send_request(self, request):
        prepared_request = self.prepare_request(request)
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

    def prepare_request(self, request):
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
