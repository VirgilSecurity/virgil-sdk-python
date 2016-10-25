import io
import unittest

from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.cryptography.hashes import Fingerprint

class FingerptintTest(unittest.TestCase):
    @property
    def _crypto(self):
        return VirgilCrypto()

    def test_from_to_hex(self):
        data = bytearray([1, 2, 3])
        fingerprint = self._crypto.calculate_fingerprint(data)
        hex_string = fingerprint.to_hex
        rebuilt_fingerprint = Fingerprint.from_hex(hex_string)
        self.assertEqual(
            fingerprint.value,
            rebuilt_fingerprint.value
        )

