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

from virgil_crypto.card_crypto import CardCrypto

from virgil_sdk import CardManager, VirgilCardVerifier
from virgil_sdk.jwt.providers import CallbackJwtProvider
from virgil_sdk.tests import BaseTest
from virgil_sdk.utils import Utils
from virgil_sdk.verification import WhiteList, VerifierCredentials


class CardVerifierTest(BaseTest):

    def test_compatibilty_card_verification_white_lists(self):
        # STC-10
        validator = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_verifier = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-10.as_string"])
        private_key_1 = self._crypto.import_private_key(
            bytearray(Utils.b64decode(self._compatibility_data["STC-10.private_key1_base64"]))
        )
        public_key_1 = self._crypto.extract_public_key(private_key_1)
        public_key_1_base64 = Utils.b64encode(self._crypto.export_public_key(public_key_1))

        key_pair_2 = self._crypto.generate_keys()
        public_key_2_base64 = Utils.b64encode(self._crypto.export_public_key(key_pair_2.public_key))

        key_pair_3 = self._crypto.generate_keys()
        public_key_3_base64 = Utils.b64encode(self._crypto.export_public_key(key_pair_3.public_key))

        self.assertTrue(card_verifier.verify_card(card_from_string))

        card_verifier.verify_self_signature = True
        self.assertTrue(card_verifier.verify_card(card_from_string))

        card_verifier.verify_virgil_signature = True
        self.assertTrue(card_verifier.verify_card(card_from_string))

        creds_1 = VerifierCredentials(signer="extra", public_key_base64=public_key_1_base64)
        white_list_1 = WhiteList(creds_1)
        card_verifier.white_lists = [white_list_1]
        self.assertTrue(card_verifier.verify_card(card_from_string))

        creds_2_1 = VerifierCredentials(signer="extra", public_key_base64=public_key_1_base64)
        creds_2_2 = VerifierCredentials(signer="test1", public_key_base64=public_key_2_base64)
        white_list_2 = WhiteList([creds_2_1, creds_2_2])
        card_verifier.white_lists = [white_list_2]
        self.assertTrue(card_verifier.verify_card(card_from_string))

        creds_3_1 = VerifierCredentials(signer="extra", public_key_base64=public_key_1_base64)
        creds_3_2 = VerifierCredentials(signer="test1", public_key_base64=public_key_2_base64)
        creds_3_3 = VerifierCredentials(signer="test1", public_key_base64=public_key_3_base64)
        white_list_3_1 = WhiteList([creds_3_1, creds_3_2])
        white_list_3_2 = WhiteList(creds_3_3)
        card_verifier.white_lists = [white_list_3_1, white_list_3_2]
        self.assertFalse(card_verifier.verify_card(card_from_string))

    def test_compatibilty_card_verification_self_sign_failed(self):
        # STC-11
        validator = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_verifier = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-11.as_string"])
        self.assertTrue(card_verifier.verify_card(card_from_string))
        card_verifier.verify_self_signature = True
        self.assertFalse(card_verifier.verify_card(card_from_string))

    def test_compatibilty_card_verification_virgil_sign_failed(self):
        # STC-12
        validator = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_verifier = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-12.as_string"])
        self.assertTrue(card_verifier.verify_card(card_from_string))
        card_verifier.verify_virgil_signature = True
        self.assertFalse(card_verifier.verify_card(card_from_string))

    def test_compatibilty_card_verification_virgil_sign_failed_2(self):
        # STC-14
        validator = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_verifier = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=True,
            white_lists=[]
        )
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-14.as_string"])
        self.assertFalse(card_verifier.verify_card(card_from_string))

    def test_compatibilty_card_verification_self_sign_failed_2(self):
        # STC-15
        validator = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_verifier = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=True,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-15.as_string"])
        self.assertFalse(card_verifier.verify_card(card_from_string))

    def test_compatibilty_card_verification_invalid_custom_sign(self):
        # STC-16
        validator = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_verifier = VirgilCardVerifier(
            CardCrypto(),
            verify_self_signature=False,
            verify_virgil_signature=False,
            white_lists=[]
        )
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-16.as_string"])
        public_key_1_base64 = self._compatibility_data["STC-16.public_key1_base64"]
        key_pair_2 = self._crypto.generate_keys()
        public_key_2_base64 = Utils.b64encode(self._crypto.export_public_key(key_pair_2.public_key))

        creds_1 = VerifierCredentials(signer="extra", public_key_base64=public_key_2_base64)
        card_verifier.white_lists = [WhiteList(creds_1)]
        self.assertFalse(card_verifier.verify_card(card_from_string))

        creds_2 = VerifierCredentials(signer="extra", public_key_base64=public_key_1_base64)
        card_verifier.white_lists = WhiteList(creds_2)
        self.assertTrue(card_verifier.verify_card(card_from_string))
