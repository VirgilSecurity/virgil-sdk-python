import io
import unittest

from virgil_sdk.cryptography import crypto
from virgil_sdk.cryptography.crypto import Crypto

class CryptoTest(unittest.TestCase):

    def test_strtobytes(self):
        self.assertEqual(Crypto.strtobytes('test'), [116, 101, 115, 116])

    def test_import_private_key(self):
        key_pair = Crypto.generate_keys()
        private_key_data = key_pair.private_key.value
        self.assertEqual(
            Crypto.import_private_key(private_key_data),
            key_pair.private_key
        )

    def test_import_public_key(self):
        key_pair = Crypto.generate_keys()
        public_key_data = key_pair.public_key.value
        self.assertEqual(
            Crypto.import_public_key(public_key_data),
            key_pair.public_key
        )

    def test_export_and_import_private_key_with_password(self):
        password = '123456'
        key_pair = Crypto.generate_keys()
        exported_private_key = Crypto.export_private_key(
            key_pair.private_key,
            password
        )
        self.assertNotEqual(
            exported_private_key,
            key_pair.private_key.value
        )
        imported_private_key = Crypto.import_private_key(
            exported_private_key,
            password
        )
        self.assertEqual(
            imported_private_key,
            key_pair.private_key
        )

    def test_export_public_key(self):
        key_pair = Crypto.generate_keys()
        exported_public_key = Crypto.export_public_key(
            key_pair.public_key
        )
        self.assertEqual(
            exported_public_key,
            key_pair.public_key.value
        )

    def test_extract_public_key(self):
        key_pair = Crypto.generate_keys()
        extracted_public_key = Crypto.extract_public_key(
            key_pair.private_key,
        )
        self.assertEqual(
            extracted_public_key,
            key_pair.public_key
        )

    def test_encrypt_and_decrypt_values(self):
        data = [1, 2, 3]
        key_pair = Crypto.generate_keys()
        encrypt_result = Crypto.encrypt(
            data,
            [key_pair.public_key]
        )
        decrypt_result = Crypto.decrypt(
            encrypt_result,
            key_pair.private_key
        )
        self.assertEqual(
            data,
            list(decrypt_result)
        )

    def test_encrypt_and_decrypt_stream(self):
        data = bytearray([1, 2, 3])
        key_pair = Crypto.generate_keys()
        encrypt_input_stream = io.BytesIO(data)
        encrypt_output_stream = io.BytesIO()
        Crypto.encrypt_stream(
            encrypt_input_stream,
            encrypt_output_stream,
            [key_pair.public_key]
        )
        encrypt_stream_result = encrypt_output_stream.getvalue()
        decrypt_input_stream = io.BytesIO(encrypt_stream_result)
        decrypt_output_stream = io.BytesIO()
        Crypto.decrypt_stream(
            decrypt_input_stream,
            decrypt_output_stream,
            key_pair.private_key
        )
        decrypt_stream_result = decrypt_output_stream.getvalue()
        self.assertEqual(
            data,
            decrypt_stream_result
        )

    def test_sign_and_verify_values(self):
        data = [1, 2, 3]
        key_pair = Crypto.generate_keys()
        signature = Crypto.sign(
            data,
            key_pair.private_key
        )
        verified = Crypto.verify(
            data,
            signature,
            key_pair.public_key
        )
        self.assertTrue(verified)

    def test_sign_and_verify_stream(self):
        data = bytearray([1, 2, 3])
        key_pair = Crypto.generate_keys()
        sign_input_stream = io.BytesIO(data)
        signature = Crypto.sign_stream(
            sign_input_stream,
            key_pair.private_key
        )
        verify_input_stream = io.BytesIO(data)
        verified = Crypto.verify_stream(
            verify_input_stream,
            signature,
            key_pair.public_key
        )
        self.assertTrue(verified)

    def test_calculate_fingerprint(self):
        data = bytearray([1, 2, 3])
        fingerprint = Crypto.calculate_fingerprint(data)
        self.assertTrue(fingerprint.value)
        self.assertIsInstance(fingerprint, crypto.Fingerprint)
