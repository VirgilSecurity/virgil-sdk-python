from VirgilSDK.virgil_crypto import virgil_crypto_python as native

class HashAlgorithm(object):
    class UnknownAlgorithmException(Exception):
        def __init__(self, algorithm):
            super(HashAlgorithm.UnknownAlgorithmException, self).__init__(algorithm)
            self.algorithm = algorithm

        def __str__(self):
            return "KeyPairType not found: %i" % self.algorithm
    MD5 = 0
    SHA1 = 1
    SHA224 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5

    ALGORITHMS_TO_NATIVE = {
        MD5: native.VirgilHash.Algorithm_MD5,
        SHA1: native.VirgilHash.Algorithm_SHA1,
        SHA224: native.VirgilHash.Algorithm_SHA224,
        SHA256: native.VirgilHash.Algorithm_SHA256,
        SHA384: native.VirgilHash.Algorithm_SHA384,
        SHA512: native.VirgilHash.Algorithm_SHA512,
    }

    @classmethod
    def convert_to_native(cls, algorithm):
        if algorithm in cls.ALGORITHMS_TO_NATIVE:
            return cls.ALGORITHMS_TO_NATIVE[algorithm]
        raise cls.UnknownAlgorithmException(algorithm)

class Fingerprint(object):
    def __init__(self, fingerprint_data):
        self._fingerprint_data = fingerprint_data

    @classmethod
    def from_hex(cls, fingerprint_hex):
        data = native.VirgilByteArrayUtils.hexToBytes(fingerprint_hex)
        return cls(data)

    @property
    def value(self):
        return self._fingerprint_data

    @property
    def hex_value(self):
        hex_data = native.VirgilByteArrayUtils.bytesToHex(self.value)
        return hex_data
