from VirgilSDK.virgil_crypto.virgil_crypto_python import VirgilDataSink
from VirgilSDK.virgil_crypto.virgil_crypto_python import VirgilDataSource

class VirgilStreamDataSink(VirgilDataSink):
    def __init__(self, stream):
        super(VirgilStreamDataSink, self).__init__()
        self.stream = stream

    def isGood(self):
        return self.stream.writable()

    def write(self, data):
        try:
            self.stream.write(bytearray(data))
        except Exception as e:
            print e


class VirgilStreamDataSource(VirgilDataSource):
    def __init__(self, stream, buffer_size=1024):
        super(VirgilStreamDataSource, self).__init__()
        self.stream = stream
        self.has_data = True
        self.buffer = bytearray(buffer_size)

    def hasData(self):
        return self.stream.readable() and self.has_data

    def read(self):
        read_count = self.stream.readinto(self.buffer)
        if not read_count:
            self.has_data = False
            return []
        return self.buffer[0:read_count]
