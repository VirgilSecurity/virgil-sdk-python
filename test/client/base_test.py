import io
import unittest
from . import config

from virgil_sdk.cryptography import VirgilCrypto

class BaseTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BaseTest, self).__init__(*args, **kwargs)
        self.__app_private_key = None
        self.__crypto = None

    @property
    def _crypto(self):
        if self.__crypto:
            return self.__crypto
        self.__crypto = VirgilCrypto()
        return self.__crypto

    @property
    def _app_private_key(self):
        if self.__app_private_key:
            return self.__app_private_key
        with open(config.VIRGIL_APP_KEY_PATH, "r") as key_file:
            raw_private_key = self._crypto.strtobytes(key_file.read())

        self.__app_private_key = self._crypto.import_private_key(
            key_data=raw_private_key,
            password=config.VIRGIL_APP_KEY_PASSWORD
        )
        return self.__app_private_key
