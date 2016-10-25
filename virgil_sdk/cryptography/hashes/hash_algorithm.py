import virgil_crypto

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
        MD5: virgil_crypto.VirgilHash.Algorithm_MD5,
        SHA1: virgil_crypto.VirgilHash.Algorithm_SHA1,
        SHA224: virgil_crypto.VirgilHash.Algorithm_SHA224,
        SHA256: virgil_crypto.VirgilHash.Algorithm_SHA256,
        SHA384: virgil_crypto.VirgilHash.Algorithm_SHA384,
        SHA512: virgil_crypto.VirgilHash.Algorithm_SHA512,
    }

    @classmethod
    def convert_to_native(cls, algorithm):
        if algorithm in cls.ALGORITHMS_TO_NATIVE:
            return cls.ALGORITHMS_TO_NATIVE[algorithm]
        raise cls.UnknownAlgorithmException(algorithm)
