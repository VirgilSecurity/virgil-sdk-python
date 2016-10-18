import sys
PYTHON_VERSION = sys.version_info[0]
if PYTHON_VERSION == 3:
    import urllib.request as urllib2
else:
    import urllib2

class RequestWithMethod(urllib2.Request, object):
    def __init__(self, *args, **kwargs):
        self._method = kwargs.pop('method', None)
        super(RequestWithMethod, self).__init__(*args, **kwargs)

    def get_method(self):
        if self._method:
            return self._method
        else:
            return super(RequestWithMethod, self).get_method()
