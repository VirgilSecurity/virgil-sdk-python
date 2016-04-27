from VirgilSDK.virgil_crypto.cryptolib import *


class ValidationTokenGenerator:
    @staticmethod
    def generate(identity_value, identity_type, private_key, password):
        signature = CryptoWrapper.sign(identity_type + identity_value, private_key, password)
        return base64.b64encode(bytearray(signature))

