from VirgilSDK.virgil_crypto.cryptolib import *
from VirgilSDK.helper import Helper


class ValidationTokenGenerator:
    @staticmethod
    def generate(identity_value, identity_type, private_key, password):
        random_id = Helper.generate_id()
        signature = base64.b64encode(bytearray(
            CryptoWrapper.sign(random_id + identity_type + identity_value, private_key, password)))
        token = random_id + '.' + signature.decode()
        return base64.b64encode(bytearray(token, 'utf-8')).decode()

