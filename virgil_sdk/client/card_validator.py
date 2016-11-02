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
from virgil_sdk.client.utils import Utils

class CardValidator(object):
    """Class used for cards signatures validation."""

    _SERVICE_CARD_ID = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853"
    _SERVICE_PUBLIC_KEY = ("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAx"
                           "a1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5E"
                           "IFBVQkxJQyBLRVktLS0tLQo=")

    def __init__(self, crypto):
        # type: (VirgilCrypto) -> None
        self.crypto = crypto
        public_key_bytes = Utils.b64tobytes(self._SERVICE_PUBLIC_KEY)
        public_key = crypto.import_public_key(public_key_bytes)
        self._verifiers = {
            self._SERVICE_CARD_ID: public_key
        }

    @property
    def verifiers(self):
        # type: () -> Dict[str, PublicKey]
        """Verifiers dict used for validation."""
        return self._verifiers

    def add_verifier(self, card_id, public_key):
        # type: (str, PublicKey) -> None
        """Add signature verifier.

        Args:
            card_id: Card identifier
            public_key: Public key used for signature verification.
        """
        self._verifiers[card_id] = public_key

    def is_valid(self, card):
        # type: (str, Card) -> bool
        """Validates Card using verifiers.

        Args:
            card: Card for validation.
        Returns:
            True if card signatures are valid, false otherwise.
        """
        if card.version == "3.0":
            return True
        fingerprint = self.crypto.calculate_fingerprint(
            Utils.strtobytes(card.snapshot)
        )
        fingerprint_hex = fingerprint.to_hex
        if fingerprint_hex != card.id:
            return False
        verifiers = self.verifiers.copy()
        card_public_key = self.crypto.import_public_key(card.public_key)
        verifiers[fingerprint_hex] = card_public_key
        for key in verifiers:
            if key not in card.signatures:
                return False
            is_valid = self.crypto.verify(
                fingerprint.value,
                Utils.b64tobytes(card.signatures[key]),
                verifiers[key]
            )
            if not is_valid:
                return False
        return True
