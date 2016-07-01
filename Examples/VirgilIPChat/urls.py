import urllib2
import json


class Urls:
    def request(self, method, url, headers=None, values=None):
        data = None
        if values:
            data = json.dumps(values).encode()
        if headers:
            req = urllib2.Request(url, data=data, headers=headers)
        else:
            req = urllib2.Request(url, data=data)
        req.get_method = lambda: method
        try:
            response = urllib2.urlopen(req)
            return response.read()
        except urllib2.HTTPError as e:
            try:
                error_res = e.read()
                raise TypeError(error_res)
            except ValueError:
                raise e