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

from virgil_sdk.signers.model_signer import ModelSigner
from virgil_sdk.utils import Utils
from .card_verifier import CardVerifier


class VirgilCardVerifier(CardVerifier):
    """
    The VirgilCardVerifier represents card verification process.
    """

    def __init__(
        self,
        crypto,
        verify_self_signature=True,  # type: bool
        verify_virgil_signature=True,  # type: bool
        white_lists=list()  # type: List[WhiteList]
    ):
        self._crypto = crypto
        self.verify_self_signature = verify_self_signature
        self.verify_virgil_signature = verify_virgil_signature
        self.__white_lists = white_lists
        self.__virgil_public_key_base64 = "MCowBQYDK2VwAyEAljOYGANYiVq1WbvVvoYIKtvZi2ji9bAhxyu6iV/LF8M="

    def verify_card(self, card):
        # type: (Card) -> bool
        """
        To verify the specified card.

        To set up rule for verification of self signature use verify_self_signature.
        To set up rule for verification of virgil service signature use verify_virgil_signature.
        To set up Whitelists use white_lists.

        Args:
            card: The instance of Card to verify.

        Returns:
            True is card is verified according to set rules, otherwise False.
        """
        if self.verify_self_signature and not self.__validate_signer_signature(
                card,
                card.public_key,
                ModelSigner.SELF_SIGNER
        ):
            return False

        if self.verify_virgil_signature and not self.__validate_signer_signature(
                card,
                self.__get_public_key(self.__virgil_public_key_base64),
                ModelSigner.VIRGIL_SIGNER
        ):
            return False

        if not any(self.white_lists):
            return True

        signers = list(map(lambda x: x.signer, card.signatures))
        verifiers_credentials_lists = list(map(lambda x: x.verifiers_credentials, self.white_lists))

        for verifiers_credentials in verifiers_credentials_lists:

            intersected_creds = list(filter(lambda x: x.signer in signers, verifiers_credentials))

            if not any(intersected_creds):
                return False

            for intersected_cred in intersected_creds:
                signer_public_key = self.__get_public_key(intersected_cred.public_key_base64)
                if self.__validate_signer_signature(card, signer_public_key, intersected_cred.signer):
                    break
                if intersected_cred is intersected_creds[-1]:
                    return False
        return True

    def __get_public_key(self, signer_public_key_base64):
        public_key_bytes = Utils.b64_decode(signer_public_key_base64)
        return self._crypto.import_public_key(bytearray(public_key_bytes))

    def __validate_signer_signature(self, card, signer_public_key, signer_type):
        signature = None
        for sign in card.signatures:
            if sign.signer == signer_type:
                signature = sign
                break

        if signature:
            if signature.snapshot:
                extended_snapshot = bytearray(Utils.b64_decode(card.content_snapshot))\
                                    + bytearray(Utils.b64_decode(signature.snapshot))
            else:
                extended_snapshot = bytearray(Utils.b64_decode(card.content_snapshot))

            if self._crypto.verify_signature(
                bytearray(signature.signature),
                extended_snapshot,
                signer_public_key
            ):
                return True
        return False

    @property
    def white_lists(self):
        """Get white lists."""
        return self.__white_lists

    @white_lists.setter
    def white_lists(self, value):
        if value:
            self.__white_lists = list()
            if not isinstance(value, list):
                self.__white_lists += [value]
            else:
                self.__white_lists += value
