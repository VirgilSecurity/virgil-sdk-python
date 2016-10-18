class Request(object):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'

    def __init__(self, endpoint, body=None, method=None, headers=None):
        self.endpoint = endpoint
        self.body = body
        self.headers = headers if headers else {}
        self.method = method
