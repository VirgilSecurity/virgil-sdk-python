import base64
import json

class Utils(object):
    @staticmethod
    def b64encode(source):
        return base64.b64encode(bytearray(source))

    @staticmethod
    def b64decode(source):
        return base64.b64decode(bytearray(source, "utf-8"))

    @staticmethod
    def json_loads(source):
        return json.loads(bytearray(source).decode())
