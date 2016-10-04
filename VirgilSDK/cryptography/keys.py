from collections import namedtuple
from VirgilSDK.virgil_crypto import virgil_crypto_python as native

KeyPair = namedtuple('KeyPair', ['private_key', 'public_key'])


PrivateKey = namedtuple('PrivateKey', ['receiver_id', 'value'])


PublicKey = namedtuple('PublicKey', ['receiver_id', 'value'])


class KeyPairType(object):
    class UnknownTypeException(Exception):
        def __init__(self, key_pair_type):
            super(KeyPairType.UnknownTypeException, self).__init__(key_pair_type)
            self.key_pair_type = key_pair_type

        def __str__(self):
            return "KeyPairType not found: %i" % self.key_pair_type

    Default = 0
    RSA_2048 = 1
    RSA_3072 = 2
    RSA_4096 = 3
    RSA_8192 = 4
    EC_SECP256R1 = 5
    EC_SECP384R1 = 6
    EC_SECP521R1 = 7
    EC_BP256R1 = 8
    EC_BP384R1 = 9
    EC_BP512R1 = 10
    EC_SECP256K1 = 11
    EC_CURVE25519 = 12
    FAST_EC_X25519 = 13
    FAST_EC_ED25519 = 14

    TYPES_TO_NATIVE = {
        Default: native.VirgilKeyPair.Type_FAST_EC_ED25519,
        RSA_2048: native.VirgilKeyPair.Type_RSA_2048,
        RSA_3072: native.VirgilKeyPair.Type_RSA_3072,
        RSA_4096: native.VirgilKeyPair.Type_RSA_4096,
        RSA_8192: native.VirgilKeyPair.Type_RSA_8192,
        EC_SECP256R1: native.VirgilKeyPair.Type_EC_SECP256R1,
        EC_SECP384R1: native.VirgilKeyPair.Type_EC_SECP384R1,
        EC_SECP521R1: native.VirgilKeyPair.Type_EC_SECP521R1,
        EC_BP256R1: native.VirgilKeyPair.Type_EC_BP256R1,
        EC_BP384R1: native.VirgilKeyPair.Type_EC_BP384R1,
        EC_BP512R1: native.VirgilKeyPair.Type_EC_BP512R1,
        EC_SECP256K1: native.VirgilKeyPair.Type_EC_SECP256K1,
        EC_CURVE25519: native.VirgilKeyPair.Type_EC_CURVE25519,
        FAST_EC_X25519: native.VirgilKeyPair.Type_FAST_EC_X25519,
        FAST_EC_ED25519: native.VirgilKeyPair.Type_FAST_EC_ED25519,
    }

    @classmethod
    def convert_to_native(cls, key_pair_type):
        if key_pair_type in cls.TYPES_TO_NATIVE:
            return cls.TYPES_TO_NATIVE[key_pair_type]
        raise cls.UnknownTypeException(key_pair_type)

