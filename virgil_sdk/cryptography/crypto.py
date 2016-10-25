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

    _CUSTOM_PARAM_KEY_SIGNATURE = None

    class SignatureIsNotValid(Exception):
        """Exception raised when Signature is not valid"""
        def __init__(self):
            super(VirgilCrypto.SignatureIsNotValid, self).__init__()

        def __str__(self):
            return "Signature is not valid"

    @staticmethod
    def strtobytes(source):
        """Convert string to bytes tuple used for all crypto methods.

        Args:
            source (str): String for conversion.

        Returns:
            (int, int, ...): tuple containing bytes from converted source string.
        """
        return tuple(bytearray(source, 'utf-8'))

    def generate_keys(self, key_pair_type=KeyPairType.Default):
        """Generates asymmetric key pair that is comprised of both public and private keys by specified type.

        Args:
            key_pair_type (:obj:`KeyPairType`, optional): type of the generated keys.

        Returns:
            (:obj:`KeyPair`): generated key pair.
        """
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
        """Imports the Private key from material representation.

        Args:
            key_data (:obj:`tuple` of :obj:`int`): key material representation bytes.
            password (str, optional): private key password, None by default.

        Returns:
            (:obj:`PrivateKey`): imported private key.
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
        """Imports the Public key from material representation.

        Args:
            key_data (:obj:`tuple` of :obj:`int`): key material representation bytes.

        Returns:
            (:obj:`PublicKey`): imported public key.
        """
        key_pair_id = self.compute_public_key_hash(key_data)
        public_key_data = VirgilKeyPair.publicKeyToDER(key_data)
        return PublicKey(receiver_id=key_pair_id, value=public_key_data)

    def export_private_key(self, private_key, password=None):
        """Exports the Private key into material representation.

        Args:
            private_key (:obj:`PrivateKey`): private key for export.
            password (str, optional): private key password, None by default.

        Returns:
            (:obj:`tuple` of :obj:`int`): key material representation bytes.
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
        """Exports the Public key into material representation.

        Args:
            public_key (:obj:`PublicKey`): public key for export.

        Returns:
            (:obj:`tuple` of :obj:`int`): key material representation bytes.
        """
        return VirgilKeyPair.publicKeyToDER(public_key.value)

    @staticmethod
    def extract_public_key(private_key):
        """Extracts the Public key from Private key.

        Args:
            private_key (:obj:`PrivateKey`): source private key for extraction.

        Returns:
            (:obj:`PublicKey`): exported public key.
        """
        public_key_data = VirgilKeyPair.extractPublicKey(private_key.value, [])
        public_key = PublicKey(
            receiver_id=private_key.receiver_id,
            value=VirgilKeyPair.publicKeyToDER(public_key_data)
        )
        return public_key

    @staticmethod
    def encrypt(data, recipients):
        """Encrypts the specified data using recipients Public keys.

        Args:
            data (:obj:`tuple` of :obj:`int`): raw data bytes for encryption.
            recipients (:obj:`list` of :obj:`PublicKey`): list of recipients' public keys.

        Returns:
            (:obj:`tuple` of :obj:`int`): encrypted data bytes.
        """
        cipher = VirgilCipher()
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt(cipher_data, private_key):
        """Decrypts the specified data using Private key.

        Args:
            data (:obj:`tuple` of :obj:`int`): encrypted data bytes for decryption.
            private_key (:obj:`PrivateKey`): private key for decryption.

        Returns:
            (:obj:`tuple` of :obj:`int`): decrypted data bytes.
        """
        cipher = VirgilCipher()
        decrypted_data = cipher.decryptWithKey(
            cipher_data,
            private_key.receiver_id,
            private_key.value
        )
        return decrypted_data

    def sign_then_encrypt(self, data, private_key, recipients):
        """Signs and encrypts the data.

        Args:
            data (:obj:`tuple` of :obj:`int`): data bytes for signing and encryption.
            private_key (:obj:`PrivateKey`): private key to sign the data.
            recipients (:obj:`list` of :obj:`PublicKey`): list of recipients' public keys.
                Used for data encryption.

        Returns:
            (:obj:`tuple` of :obj:`int`): signed and encrypted data bytes.
        """
        signer = VirgilSigner()
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
        """Decrypts and verifies the data.

        Args:
            data (:obj:`tuple` of :obj:`int`): encrypted data bytes.
            private_key (:obj:`PrivateKey`): private key for decryption.
            public_key (:obj:`PublicKey`): public key for verification.

        Returns:
            (:obj:`tuple` of :obj:`int`): decrypted data bytes.

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

    @staticmethod
    def sign(data, private_key):
        """Signs the specified data using Private key.

        Args:
            data (:obj:`tuple` of :obj:`int`): raw data bytes for signing.
            private_key (:obj:`PrivateKey`): private key for signing.

        Returns:
            (:obj:`tuple` of :obj:`int`): signature bytes.
        """
        signer = VirgilSigner()
        signature = signer.sign(data, private_key.value)
        return signature

    @staticmethod
    def verify(data, signature, signer_public_key):
        """Verifies the specified signature using original data and signer's public key.

        Args:
            data (:obj:`tuple` of :obj:`int`): original data bytes for verification.
            signature (:obj:`tuple` of :obj:`int`): signature bytes for verification.
            signer_public_key (:obj:`PublicKey`): signer public key for verification.

        Returns:
            (bool): True if signature is valid, False otherwise.
        """
        signer = VirgilSigner()
        is_valid = signer.verify(data, signature, signer_public_key.value)
        return is_valid

    @staticmethod
    def encrypt_stream(input_stream, output_stream, recipients):
        """Encrypts the specified stream using recipients Public keys.

        Args:
            input_stream (:obj:`io.IOBase`): readable stream containing input data.
            output_stream (:obj:`io.IOBase`): writable stream for output.
            recipients (:obj:`list` of :obj:`PublicKey`): list of recipients' public keys.

        """

        cipher = VirgilChunkCipher()
        for public_key in recipients:
            cipher.addKeyRecipient(public_key.receiver_id, public_key.value)
        source = VirgilStreamDataSource(input_stream)
        sink = VirgilStreamDataSink(output_stream)
        cipher.encrypt(source, sink)

    @staticmethod
    def decrypt_stream(input_stream, output_stream, private_key):
        """Decrypts the specified stream using Private key.

        Args:
            input_stream (:obj:`io.IOBase`): readable stream containing input data.
            output_stream (:obj:`io.IOBase`): writable stream for output.
            private_key (:obj:`PrivateKey`): private key for decryption.

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

    @staticmethod
    def sign_stream(input_stream, private_key):
        """Signs the specified stream using Private key.

        Args:
            input_stream (:obj:`io.IOBase`): readable stream containing input data.
            private_key (:obj:`PrivateKey`): private key for signing.

        Returns:
            (:obj:`tuple` of :obj:`int`): signature bytes.
        """
        signer = VirgilStreamSigner()
        source = VirgilStreamDataSource(input_stream)
        signature = signer.sign(source, private_key.value)
        return signature

    @staticmethod
    def verify_stream(input_stream, signature, signer_public_key):
        """Verifies the specified signature using original stream and signer's Public key.

        Args:
            input_stream (:obj:`io.IOBase`): readable stream containing input data.
            signature (:obj:`tuple` of :obj:`int`): signature bytes for verification.
            signer_public_key (:obj:`PublicKey`): signer public key for verification.

        Returns:
            (bool): True if signature is valid, False otherwise.
        """
        signer = VirgilStreamSigner()
        source = VirgilStreamDataSource(input_stream)
        isValid = signer.verify(source, signature, signer_public_key.value)
        return isValid

    def calculate_fingerprint(self, data):
        """Calculates the fingerprint.

        Args:
            data (:obj:`tuple` of :obj:`int`): data bytes for fingerprint calculation.

        Returns:
            (:obj:`Fingerprint`): fingerprint of the source data.
        """
        hash_data = self.compute_hash(data, HashAlgorithm.SHA256)
        return Fingerprint(hash_data)

    @staticmethod
    def compute_hash(data, algorithm):
        """Computes the hash of specified data.

        Args:
            data (:obj:`tuple` of :obj:`int`): data bytes for fingerprint calculation.
            algorithm (:obj:`HashAlgorithm`): hashing algorithm.

        Returns:
            (:obj:`tuple` of :obj:`int`): hash bytes.
        """
        native_algorithm = HashAlgorithm.convert_to_native(algorithm)
        native_hasher = virgil_crypto.VirgilHash(native_algorithm)
        return native_hasher.hash(data)

    def compute_public_key_hash(self, public_key):
        """Computes the hash of specified public key using SHA256 algorithm.

        Args:
            public_key (:obj:`PublicKey`): public key for hashing.

        Returns:
            (:obj:`tuple` of :obj:`int`): hash bytes.
        """
        public_key_der = virgil_crypto.VirgilKeyPair.publicKeyToDER(public_key)
        return self.compute_hash(public_key_der, HashAlgorithm.SHA256)

    @property
    def custom_param_key_signature(self):
        """Custom param key signature.

        Returns:
            (:obj:`tuple` of :obj:`int`): `VIRGIL-DATA-SIGNATURE` bytes.
        """
        if self._CUSTOM_PARAM_KEY_SIGNATURE:
            return self._CUSTOM_PARAM_KEY_SIGNATURE
        self._CUSTOM_PARAM_KEY_SIGNATURE = self.strtobytes("VIRGIL-DATA-SIGNATURE")
        return self._CUSTOM_PARAM_KEY_SIGNATURE
