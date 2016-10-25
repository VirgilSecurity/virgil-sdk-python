import virgil_crypto

class Fingerprint(object):
    def __init__(self, fingerprint_data):
        self._fingerprint_data = fingerprint_data

    @classmethod
    def from_hex(cls, fingerprint_hex):
        data = virgil_crypto.VirgilByteArrayUtils.hexToBytes(fingerprint_hex)
        return cls(data)

    @property
    def value(self):
        return self._fingerprint_data

    @property
    def to_hex(self):
        hex_data = virgil_crypto.VirgilByteArrayUtils.bytesToHex(self.value)
        return hex_data
