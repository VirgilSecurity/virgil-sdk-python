# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
import virgil_crypto
from virgil_crypto import VirgilCipher
from virgil_crypto import VirgilChunkCipher
from virgil_crypto import VirgilKeyPair
from virgil_crypto import VirgilSigner
from virgil_crypto import VirgilStreamSigner
from virgil_crypto import VirgilStreamDataSink
from virgil_crypto import VirgilStreamDataSource
from virgil_sdk.cryptography.keys import KeyPair
from virgil_sdk.cryptography.keys import KeyPairType
from virgil_sdk.cryptography.keys import PrivateKey
from virgil_sdk.cryptography.keys import PublicKey
from virgil_sdk.cryptography.hashes import HashAlgorithm
from virgil_sdk.cryptography.hashes import Fingerprint

class VirgilCrypto(object):
    """Wrapper for cryptographic operations.

    Class provides a cryptographic operations in applications, such as hashing,
    signature generation and verification, and encryption and decryption

    """
    def __init__(self):
        self.signature_hash_algorithm = HashAlgorithm.SHA384
        self.key_pair_type = KeyPairType.Default

    _CUSTOM_PARAM_KEY_SIGNATURE = None

    class SignatureIsNotValid(Exception):
        """Exception raised when Signature is not valid"""
        def __init__(self):
            super(VirgilCrypto.SignatureIsNotValid, self).__init__()

        def __str__(self):
            return "Signature is not valid"

    @staticmethod
    def strtobytes(source):
        # type: (str) -> Tuple[*int]
        """Convert string to bytes tuple used for all crypto methods.

        Args:
            source: String for conversion.

        Returns:
            Tuple containing bytes from converted source string.
        """
        return tuple(bytearray(source, 'utf-8'))

    def generate_keys(self):
        # type: () -> KeyPair
        """Generates asymmetric key pair that is comprised of both public and private keys by specified type.

        Args:
            key_pair_type: type of the generated keys.
                The possible values can be found in KeyPairType enum.

        Returns:
            Generated key pair.
        """
        native_type = KeyPairType.convert_to_native(self.key_pair_type)
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
        # type: (Tuple[*int], Optional[str]) -> PrivateKey
        """Imports the Private key from material representation.

        Args:
            key_data: key material representation bytes.
            password: private key password, None by default.

        Returns:
            Imported private key.
        """
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
        # type: (Tuple[*int]) -> PublicKey
        """Imports the Public key from material representation.

        Args:
            key_data: key material representation bytes.

        Returns:
            Imported public key.
        """
        key_pair_id = self.compute_public_key_hash(key_data)
        public_key_data = VirgilKeyPair.publicKeyToDER(key_data)
        return PublicKey(receiver_id=key_pair_id, value=public_key_data)

    def export_private_key(self, private_key, password=None):
        # type: (PrivateKey, Optional[str]) -> Tuple[*int]
        """Exports the Private key into material representation.

        Args:
            private_key: private key for export.
            password: private key password, None by default.

        Returns:
            Key material representation bytes.
        """
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
        # type: (PublicKey) -> Tuple[*int]
        """Exports the Public key into material representation.

        Args:
            public_key: public key for export.

        Returns:
            Key material representation bytes.
        """
        return VirgilKeyPair.publicKeyToDER(public_key.value)

    @staticmethod
    def extract_public_key(private_key):
        # type: (PrivateKey) -> PublicKey
        """Extracts the Public key from Private key.

        Args:
            private_key: source private key for extraction.

        Returns:
            Exported public key.
        """
        public_key_data = VirgilKeyPair.extractPublicKey(private_key.value, [])
        public_key = PublicKey(
            receiver_id=private_key.receiver_id,
            value=VirgilKeyPair.publicKeyToDER(public_key_data)
        )
        return public_key

    @staticmethod
    def encrypt(data, *recipients):
        # type: (Tuple[*int], List[PublicKey]) -> Tuple[*int]
        """Encrypts the specified data using recipients Public keys.

        Args:
            data: raw data bytes for encryption.
            recipients: list of recipients' public keys.

        Returns:
            Encrypted data bytes.
        """
        cipher = VirgilCipher()
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt(cipher_data, private_key):
        # type: (Tuple[*int], PrivateKey) -> Tuple[*int]
        """Decrypts the specified data using Private key.

        Args:
            data: encrypted data bytes for decryption.
            private_key: private key for decryption.

        Returns:
            Decrypted data bytes.
        """
        cipher = VirgilCipher()
        decrypted_data = cipher.decryptWithKey(
            cipher_data,
            private_key.receiver_id,
            private_key.value
        )
        return decrypted_data

    def sign_then_encrypt(self, data, private_key, *recipients):
        # type: (Tuple[*int], PrivateKey, List[PublicKey]) -> Tuple[*int]
        """Signs and encrypts the data.

        Args:
            data: data bytes for signing and encryption.
            private_key: private key to sign the data.
            recipients: list of recipients' public keys.
                Used for data encryption.

        Returns:
            Signed and encrypted data bytes.
        """
        signer = VirgilSigner(self.signature_hash_algorithm)
        signature = signer.sign(data, private_key.value)
        cipher = VirgilCipher()
        custom_data = cipher.customParams()
        custom_data.setData(
            self.custom_param_key_signature,
            signature
        )
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        return cipher.encrypt(data)

    def decrypt_then_verify(self, data, private_key, public_key):
        # type: (Tuple[*int], PrivateKey, PublicKey) -> Tuple[*int]
        """Decrypts and verifies the data.

        Args:
            data: encrypted data bytes.
            private_key: private key for decryption.
            public_key: public key for verification.

        Returns:
            Decrypted data bytes.

        Raises:
            SignatureIsNotValid: if signature is not verified.
        """
        cipher = VirgilCipher()
        decrypted_data = cipher.decryptWithKey(
            data,
            private_key.receiver_id,
            private_key.value
        )
        signature = cipher.customParams().getData(self.custom_param_key_signature)
        is_valid = self.verify(decrypted_data, signature, public_key)
        if not is_valid:
            raise self.SignatureIsNotValid()
        return decrypted_data

    def sign(self, data, private_key):
        # type: (Tuple[*int], PrivateKey) -> Tuple[*int]
        """Signs the specified data using Private key.

        Args:
            data: raw data bytes for signing.
            private_key: private key for signing.

        Returns:
            Signature bytes.
        """
        signer = VirgilSigner(self.signature_hash_algorithm)
        signature = signer.sign(data, private_key.value)
        return signature

    def verify(self, data, signature, signer_public_key):
        # type: (Tuple[*int], Tuple[*int], PublicKey) -> bool
        """Verifies the specified signature using original data and signer's public key.

        Args:
            data: original data bytes for verification.
            signature: signature bytes for verification.
            signer_public_key: signer public key for verification.

        Returns:
            True if signature is valid, False otherwise.
        """
        signer = VirgilSigner(self.signature_hash_algorithm)
        is_valid = signer.verify(data, signature, signer_public_key.value)
        return is_valid

    @staticmethod
    def encrypt_stream(input_stream, output_stream, *recipients):
        # type: (io.IOBase, io.IOBase, List[PublicKey]) -> None
        """Encrypts the specified stream using recipients Public keys.

        Args:
            input_stream: readable stream containing input data.
            output_stream: writable stream for output.
            recipients: list of recipients' public keys.

        """

        cipher = VirgilChunkCipher()
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        source = VirgilStreamDataSource(input_stream)
        sink = VirgilStreamDataSink(output_stream)
        cipher.encrypt(source, sink)

    @staticmethod
    def decrypt_stream(input_stream, output_stream, private_key):
        # type: (io.IOBase, io.IOBase, PrivateKey) -> None
        """Decrypts the specified stream using Private key.

        Args:
            input_stream: readable stream containing input data.
            output_stream: writable stream for output.
            private_key: private key for decryption.

        """
        cipher = VirgilChunkCipher()
        source = VirgilStreamDataSource(input_stream)
        sink = VirgilStreamDataSink(output_stream)
        cipher.decryptWithKey(
            source,
            sink,
            private_key.receiver_id,
            private_key.value
        )

    def sign_stream(self, input_stream, private_key):
        # type: (io.IOBase, PrivateKey) -> Tuple[*int]
        """Signs the specified stream using Private key.

        Args:
            input_stream: readable stream containing input data.
            private_key: private key for signing.

        Returns:
            Signature bytes.
        """
        signer = VirgilStreamSigner(self.signature_hash_algorithm)
        source = VirgilStreamDataSource(input_stream)
        signature = signer.sign(source, private_key.value)
        return signature

    def verify_stream(self, input_stream, signature, signer_public_key):
        # type: (io.IOBase, Tuple[*int], PublicKey) -> bool
        """Verifies the specified signature using original stream and signer's Public key.

        Args:
            input_stream: readable stream containing input data.
            signature: signature bytes for verification.
            signer_public_key: signer public key for verification.

        Returns:
            True if signature is valid, False otherwise.
        """
        signer = VirgilStreamSigner(self.signature_hash_algorithm)
        source = VirgilStreamDataSource(input_stream)
        is_valid = signer.verify(source, signature, signer_public_key.value)
        return is_valid

    def calculate_fingerprint(self, data):
        # type: (Tuple[*int]) -> Fingerprint
        """Calculates the fingerprint.

        Args:
            data: data bytes for fingerprint calculation.

        Returns:
            Fingerprint of the source data.
        """
        hash_data = self.compute_hash(data, HashAlgorithm.SHA256)
        return Fingerprint(hash_data)

    @staticmethod
    def compute_hash(data, algorithm):
        # type: (Tuple[*int], int) -> Tuple[*int]
        """Computes the hash of specified data.

        Args:
            data: data bytes for fingerprint calculation.
            algorithm: hashing algorithm.
                The possible values can be found in HashAlgorithm enum.

        Returns:
            Hash bytes.
        """
        native_algorithm = HashAlgorithm.convert_to_native(algorithm)
        native_hasher = virgil_crypto.VirgilHash(native_algorithm)
        return native_hasher.hash(data)

    def compute_public_key_hash(self, public_key):
        # type: (PublicKey) -> Tuple[*int]
        """Computes the hash of specified public key using SHA256 algorithm.

        Args:
            public_key: public key for hashing.

        Returns:
            Hash bytes.
        """
        public_key_der = virgil_crypto.VirgilKeyPair.publicKeyToDER(public_key)
        return self.compute_hash(public_key_der, HashAlgorithm.SHA256)

    @property
    def custom_param_key_signature(self):
        # type: () -> Tuple[*int]
        """Custom param key signature.

        Returns:
            `VIRGIL-DATA-SIGNATURE` bytes.
        """
        if self._CUSTOM_PARAM_KEY_SIGNATURE:
            return self._CUSTOM_PARAM_KEY_SIGNATURE
        self._CUSTOM_PARAM_KEY_SIGNATURE = self.strtobytes("VIRGIL-DATA-SIGNATURE")
        return self._CUSTOM_PARAM_KEY_SIGNATURE
