# Copyright (C) 2016-2019 Virgil Security Inc.
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
import os

from virgil_crypto.card_crypto import CardCrypto

from virgil_sdk.tests.base_test import BaseTest
from virgil_sdk.signers import ModelSigner
from virgil_sdk.utils.utils import Utils


class ModelSignerTest(BaseTest):

    def test_self_sign_valid_signature(self):
        # STC-8
        self_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(self_key_pair)
        signer = ModelSigner(CardCrypto())
        self.assertEqual(len(raw_signed_model.signatures), 0)
        signer.self_sign(raw_signed_model, self_key_pair.private_key)
        self.assertEqual(len(raw_signed_model.signatures), 1)
        self_signature = raw_signed_model.signatures[0]
        self.assertEqual(self_signature.signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(self_signature.snapshot, None)
        self.assertTrue(
            self._crypto.verify(
                bytearray(Utils.b64_decode(raw_signed_model.content_snapshot)),
                self_signature.signature, self_key_pair.public_key
            )
        )

    def test_self_sign_signature_snapshot_valid_signature(self):
        # STC-9
        self_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(self_key_pair)
        signer = ModelSigner(CardCrypto())
        self.assertEqual(len(raw_signed_model.signatures), 0)
        signature_snapshot = os.urandom(32)
        signer.self_sign(raw_signed_model, self_key_pair.private_key, signature_snapshot=signature_snapshot)
        self_signature = raw_signed_model.signatures[0]
        self.assertEqual(self_signature.signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(self_signature.snapshot, signature_snapshot)

    def test_second_self_sign_exception(self):
        # STC-8
        self_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(self_key_pair, add_self_sign=True)
        signer = ModelSigner(CardCrypto())
        self.assertRaises(ValueError, signer.self_sign, raw_signed_model, self_key_pair.private_key)

    def test_extra_sign_valid_signature(self):
        self_key_pair = self._crypto.generate_keys()
        extra_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(self_key_pair, add_self_sign=True)
        signer = ModelSigner(CardCrypto())
        self.assertEqual(len(raw_signed_model.signatures), 1)
        signer.sign(raw_signed_model, "test_id", extra_key_pair.private_key)
        self.assertEqual(len(raw_signed_model.signatures), 2)
        extra_signature = raw_signed_model.signatures[-1]
        self.assertEqual(extra_signature.signer, "test_id")
        self.assertTrue(self._crypto.verify(
                bytearray(Utils.b64_decode(raw_signed_model.content_snapshot)),
                extra_signature.signature, extra_key_pair.public_key
            )
        )

    def test_extra_sign_snapshot_valid_signature(self):
        self_key_pair = self._crypto.generate_keys()
        extra_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(self_key_pair, add_self_sign=True)
        signer = ModelSigner(CardCrypto())
        self.assertEqual(len(raw_signed_model.signatures), 1)
        signature_snapshot = os.urandom(32)
        signer.sign(raw_signed_model, "test_id", extra_key_pair.private_key, signature_snapshot=signature_snapshot)
        self.assertEqual(len(raw_signed_model.signatures), 2)
        extra_signature = raw_signed_model.signatures[-1]
        self.assertEqual(extra_signature.signer, "test_id")
        self.assertEqual(extra_signature.snapshot, signature_snapshot)
        extended_snapshot = bytearray(Utils.b64_decode(raw_signed_model.content_snapshot)) + signature_snapshot
        self.assertTrue(self._crypto.verify(
            extended_snapshot,
            extra_signature.signature,
            extra_key_pair.public_key
        ))

    def test_second_extra_sign_exception(self):
        self_key_pair = self._crypto.generate_keys()
        extra_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(
            self_key_pair, add_self_sign=True, extra_key_pair=extra_key_pair
        )
        signer = ModelSigner(CardCrypto())
        self.assertRaises(ValueError, signer.sign, raw_signed_model, "extra", extra_key_pair.private_key)
