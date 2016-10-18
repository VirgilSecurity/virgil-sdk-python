from virgil_crypto import virgil_crypto_python as native
from virgil_crypto.virgil_crypto_python import VirgilCipher
from virgil_crypto.virgil_crypto_python import VirgilChunkCipher
from virgil_crypto.virgil_crypto_python import VirgilKeyPair
from virgil_crypto.virgil_crypto_python import VirgilSigner
from virgil_crypto.virgil_crypto_python import VirgilStreamSigner
from virgil_crypto.streams import VirgilStreamDataSink
from virgil_crypto.streams import VirgilStreamDataSource
from virgil_sdk.cryptography.keys import KeyPair
from virgil_sdk.cryptography.keys import KeyPairType
from virgil_sdk.cryptography.keys import PrivateKey
from virgil_sdk.cryptography.keys import PublicKey
from virgil_sdk.cryptography.hashes import HashAlgorithm
from virgil_sdk.cryptography.hashes import Fingerprint

class VirgilCrypto(object):
    @staticmethod
    def strtobytes(source):
        return tuple(bytearray(source, 'utf-8'))

    def generate_keys(self, key_pair_type=KeyPairType.Default):
        native_type = KeyPairType.convert_to_native(key_pair_type)
        native_key_pair = VirgilKeyPair.generate(native_type)
        key_pair_id = self.compute_public_key_hash(native_key_pair.publicKey())
        private_key = PrivateKey(
            receiver_id=key_pair_id,
            value=VirgilKeyPair.privateKeyToDER(native_key_pair.privateKey())
        )
        public_key = PublicKey(
            receiver_id=key_pair_id,
            value=VirgilKeyPair.publicKeyToDER(native_key_pair.publicKey())
        )
        return KeyPair(private_key=private_key, public_key=public_key)

    def import_private_key(self, key_data, password=None):
        decrypted_private_key = None
        if not password:
            decrypted_private_key = VirgilKeyPair.privateKeyToDER(key_data)
        else:
            decrypted_private_key = VirgilKeyPair.decryptPrivateKey(
                key_data,
                self.strtobytes(password)
            )

        public_key_data = VirgilKeyPair.extractPublicKey(decrypted_private_key, [])
        key_pair_id = self.compute_public_key_hash(public_key_data)
        private_key_data = VirgilKeyPair.privateKeyToDER(decrypted_private_key)
        return PrivateKey(receiver_id=key_pair_id, value=private_key_data)

    def import_public_key(self, key_data):
        key_pair_id = self.compute_public_key_hash(key_data)
        public_key_data = VirgilKeyPair.publicKeyToDER(key_data)
        return PublicKey(receiver_id=key_pair_id, value=public_key_data)

    def export_private_key(self, private_key, password=None):
        if not password:
            return VirgilKeyPair.privateKeyToDER(private_key.value)

        password_bytes = self.strtobytes(password)
        private_key_data = VirgilKeyPair.encryptPrivateKey(
            private_key.value,
            password_bytes
        )
        return VirgilKeyPair.privateKeyToDER(private_key_data, password_bytes)

    @staticmethod
    def export_public_key(public_key):
        return VirgilKeyPair.publicKeyToDER(public_key.value)

    @staticmethod
    def extract_public_key(private_key):
        public_key_data = VirgilKeyPair.extractPublicKey(private_key.value, [])
        public_key = PublicKey(
            receiver_id=private_key.receiver_id,
            value=VirgilKeyPair.publicKeyToDER(public_key_data)
        )
        return public_key

    @staticmethod
    def encrypt(data, recipients):
        cipher = VirgilCipher()
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt(cipher_data, private_key):
        cipher = VirgilCipher()
        decrypted_data = cipher.decryptWithKey(
            cipher_data,
            private_key.receiver_id,
            private_key.value
        )
        return decrypted_data

    @staticmethod
    def sign(data, private_key):
        signer = VirgilSigner()
        signature = signer.sign(data, private_key.value)
        return signature

    @staticmethod
    def verify(data, signature, signer_public_key):
        signer = VirgilSigner()
        is_valid = signer.verify(data, signature, signer_public_key.value)
        return is_valid

    @staticmethod
    def encrypt_stream(input_stream, output_stream, recipients):
        cipher = VirgilChunkCipher()
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        source = VirgilStreamDataSource(input_stream)
        sink = VirgilStreamDataSink(output_stream)
        cipher.encrypt(source, sink)

    @staticmethod
    def decrypt_stream(input_stream, output_stream, private_key):
        cipher = VirgilChunkCipher()
        source = VirgilStreamDataSource(input_stream)
        sink = VirgilStreamDataSink(output_stream)
        cipher.decryptWithKey(
            source,
            sink,
            private_key.receiver_id,
            private_key.value
        )

    @staticmethod
    def sign_stream(input_stream, private_key):
        signer = VirgilStreamSigner()
        source = VirgilStreamDataSource(input_stream)
        signature = signer.sign(source, private_key.value)
        return signature

    @staticmethod
    def verify_stream(input_stream, signature, signer_public_key):
        signer = VirgilStreamSigner()
        source = VirgilStreamDataSource(input_stream)
        isValid = signer.verify(source, signature, signer_public_key.value)
        return isValid

    def calculate_fingerprint(self, data):
        hash_data = self.compute_hash(data, HashAlgorithm.SHA256)
        return Fingerprint(hash_data)

    @staticmethod
    def compute_hash(data, algorithm):
        native_algorithm = HashAlgorithm.convert_to_native(algorithm)
        native_hasher = native.VirgilHash(native_algorithm)
        return native_hasher.hash(data)

    def compute_public_key_hash(self, public_key):
        public_key_der = native.VirgilKeyPair.publicKeyToDER(public_key)
        return self.compute_hash(public_key_der, HashAlgorithm.SHA256)
