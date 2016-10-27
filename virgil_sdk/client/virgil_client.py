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
from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.client.http import Request
from virgil_sdk.client.http import CardsServiceConnection
from virgil_sdk.client import RequestSigner
from virgil_sdk.client import SearchCriteria
from virgil_sdk.client import Card

class VirgilClient(object):
    """Virgil API client

    Contains methods for searching and managing cards.
    """

    def __init__(self, access_token, app_id, app_key):
        # type: (str, str, PrivateKey) -> None
        """Constructs new VirgilClient object"""
        self.access_token = access_token
        self.app_id = app_id
        self.app_key = app_key
        self.cards_service_url = "https://cards.virgilsecurity.com"
        self.cards_read_only_service_url = "https://cards-ro.virgilsecurity.com"
        self._crypto = None
        self._cards_connection = None
        self._read_cards_connection = None
        self._request_signer = None

    def create_card(self, identity, identity_type, key_pair):
        # type: (str, str, KeyPair) -> Card
        """Create new card from given attributes.

        Args:
            identity: Created card identity.
            identity_type: Created card identity type.
            key_pair: Key pair of the created card.
                Public key is stored in the card, private key is used for request signing.

        Returns:
            Created card from server response.
        """
        request = CreateCardRequest(
            identity=identity,
            identity_type=identity_type,
            raw_public_key=self.crypto.export_public_key(key_pair.public_key),
        )
        self.request_signer.self_sign(request, key_pair.private_key)
        self.request_signer.authority_sign(request, self.app_id, self.app_key)

        return self.create_card_from_signed_request(request)

    def create_card_from_signed_request(self, create_request):
        # type: (CreateCardRequest) -> Card
        """Create new card from signed creation request.

        Args:
            create_request: signed card creation request.

        Returns:
            Created card from server response.
        """
        http_request = Request(
            method=Request.POST,
            endpoint="/v4/card",
            body=create_request.request_model
        )
        raw_response = self.cards_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        return card

    def revoke_card(self, card_id, reason=RevokeCardRequest.Reasons.Unspecified):
        # type: (str, str) -> None
        """Revoke card by id.

        Args:
            card_id: id of the revoked card.
            reason: card revocation reason.
                The possible values can be found in RevokeCardRequest.Reasons enum.
        """
        request = RevokeCardRequest(
            card_id=card_id,
            reason=reason,
        )
        self.request_signer.authority_sign(request, self.app_id, self.app_key)

        return self.revoke_card_from_signed_request(request)

    def revoke_card_from_signed_request(self, revocation_request):
        # type: (RevocationRequest) -> None
        """Revoke card using signed revocation request.

        Args:
            revocation_request: signed card revocation request.
        """
        http_request = Request(
            method=Request.DELETE,
            endpoint="/v4/card/%s" % revocation_request.card_id,
            body=revocation_request.request_model
        )
        self.cards_connection.send_request(http_request)

    def get_card(self, card_id):
        # type: (str) -> Card
        """Get card by id.

        Args:
            card_id: id of the card to get.

        Returns:
            Found card from server response.
        """
        http_request = Request(
            method=Request.GET,
            endpoint="/v4/card/%s" % card_id,
        )
        raw_response = self.read_cards_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        return card

    def search_cards_by_identities(self, *identities):
        # type: (*str) -> List[Card]
        """Search cards by specified identities.

        Args:
            identities: identity values for search.

        Returns:
            Found cards from server response.
        """
        return self.search_cards_by_criteria(
            SearchCriteria.by_identities(identities)
        )

    def search_cards_by_app_bundle(self, bundle):
        # type: (str) -> List[Card]
        """Search cards by specified app bundle.

        Args:
            bundle: application bundle for search.

        Returns:
            Found cards from server response.
        """
        return self.search_cards_by_criteria(
            SearchCriteria.by_app_bundle(bundle)
        )

    def search_cards_by_criteria(self, search_criteria):
        # type: (SearchCriteria) -> List[Card]
        """Search cards by specified search criteria.

        Args:
            search_criteria: constructed search criteria.

        Returns:
            Found cards from server response.
        """
        body = {"identities": search_criteria.identities}
        if search_criteria.identity_type:
            body["identity_type"] = search_criteria.identity_type
        if search_criteria.scope == Card.Scope.GLOBAL:
            body["scope"] = Card.Scope.GLOBAL
        http_request = Request(
            method=Request.POST,
            endpoint="/v4/card/actions/search",
            body=body,
        )
        response = self.read_cards_connection.send_request(http_request)
        cards = [Card.from_response(card) for card in response]
        return cards

    @property
    def cards_connection(self):
        # type: () -> CardsServiceConnection
        """Cards service connection used for creating and revoking cards."""
        if not self._cards_connection:
            self._cards_connection = CardsServiceConnection(
                self.access_token,
                self.cards_service_url
            )
        return self._cards_connection

    @property
    def read_cards_connection(self):
        # type: () -> CardsServiceConnection
        """Cards service connection used for getting and searching cards."""
        if not self._read_cards_connection:
            self._read_cards_connection = CardsServiceConnection(
                self.access_token,
                self.cards_read_only_service_url
            )
        return self._read_cards_connection

    @property
    def request_signer(self):
        # type: () -> RequestSigner
        """Request signer for signing constructed requests."""
        if not self._request_signer:
            self._request_signer = RequestSigner(self.crypto)
        return self._request_signer

    @property
    def crypto(self):
        # type: () -> VirgilCrypto
        """Crypto library wrapper."""
        if not self._crypto:
            self._crypto = VirgilCrypto()
        return self._crypto
