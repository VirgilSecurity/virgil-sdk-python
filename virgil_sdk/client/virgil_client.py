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
from virgil_sdk.client.http import RaServiceConnection
from virgil_sdk.client.requests import CreateGlobalCardRequest
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.client.http import Request
from virgil_sdk.client.http import CardsServiceConnection
from virgil_sdk.client.http import IdentityServiceConnection
from virgil_sdk.client import SearchCriteria
from virgil_sdk.client import Card


class VirgilClient(object):
    """Virgil API client

    Contains methods for searching and managing cards.
    """
    class InvalidCardException(Exception):
        """Exception raised when card is not valid"""
        def __init__(self, invalid_cards):
            super(VirgilClient.InvalidCardException, self).__init__()
            self.invalid_cards = invalid_cards

        def __str__(self):
            return "Cards {} are not valid".format(self.invalid_cards)

    def __init__(
            self,
            access_token=None,  # type: Optional[str]
            cards_service_url="https://cards.virgilsecurity.com",  # type: Optional[str]
            cards_read_only_service_url="https://cards-ro.virgilsecurity.com",  # type: Optional[str]
            identity_service_url="https://identity.virgilsecurity.com",  # type: Optional[str]
            ra_service_url="https://ra.virgilsecurity.com"  # type: Optional[str]
        ):
        # type: (str, str, str, str, str) -> None
        """Constructs new VirgilClient object"""
        self.access_token = access_token
        self.cards_service_url = cards_service_url
        self.identity_service_url = identity_service_url
        self.cards_read_only_service_url = cards_read_only_service_url
        self.ra_service_url = ra_service_url
        self._cards_connection = None
        self._identity_connection = None
        self._ra_connection = None
        self._read_cards_connection = None
        self._card_validator = None

    def create_card_from_request(self, create_request):
        # type: (CreateCardRequest) -> Card
        """Create new card from signed creation request.

        Args:
            create_request: signed card creation request.

        Returns:
            Created card from server response.

        Raises:
            VirgilClient.InvalidCardException if client has validator
            and returned card signatures are not valid.
        """
        http_request = Request(
            method=Request.POST,
            endpoint="/v4/card",
            body=create_request.request_model
        )
        raw_response = self.cards_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        if self.card_validator:
            self.validate_cards([card])
        return card

    def create_global_card_from_request(self, create_request):
        # type: (CreateGlobalCardRequest) -> Card
        """Create new global card from signed creation request.

        Args:
            create_request: signed card creation request.

        Returns:
            Created global card from server response.

        Raises:
            VirgilClient.InvalidCardException if client has validator
            and returned card signatures are not valid.
        """
        http_request = Request(
            method=Request.POST,
            endpoint="/v1/card",
            body=create_request.request_model
        )
        raw_response = self.ra_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        if self.card_validator:
            self.validate_cards([card])
        return card

    def revoke_card_from_request(self, revocation_request):
        # type: (RevokeCardRequest) -> None
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

    def revoke_global_card_from_request(self, revocation_request):
        # type: (RevokeGlobalCardRequest) -> None
        """Revoke global card using signed revocation request.

        Args:
            revocation_request: signed card revocation request.
        """
        http_request = Request(
            method=Request.DELETE,
            endpoint="/v1/card/%s" % revocation_request.card_id,
            body=revocation_request.request_model
        )
        self.ra_connection.send_request(http_request)

    def get_card(self, card_id):
        # type: (str) -> Card
        """Get card by id.

        Args:
            card_id: id of the card to get.

        Returns:
            Found card from server response.

        Raises:
            VirgilClient.InvalidCardException if client has validator
            and retrieved card signatures are not valid.
        """
        http_request = Request(
            method=Request.GET,
            endpoint="/v4/card/%s" % card_id,
        )
        raw_response = self.read_cards_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        if self.card_validator:
            self.validate_cards([card])
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

    def search_cards_by_criteria(self, search_criteria):
        # type: (SearchCriteria) -> List[Card]
        """Search cards by specified search criteria.

        Args:
            search_criteria: constructed search criteria.

        Returns:
            Found cards from server response.

        Raises:
            VirgilClient.InvalidCardException if client has validator
            and cards are not valid.
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
        if self.card_validator:
            self.validate_cards(cards)
        return cards

    def verify_identity(self, identity, identity_type, extra_fields=None):
        # type: (str, str, dict) -> str
        """Sends the request for identity verification, that's will be processed depending of specified type.
        Args:
            identity: An unique string that represents identity.
            identity_type: The type of identity.
            extra_fields: The extra fields.
        Returns:
            Action id that will be used in confirm identity
        """
        body = {"value": identity, "type": identity_type}
        if extra_fields:
            body["extra_fields"] = extra_fields

        http_request = Request(
            method=Request.POST,
            endpoint="/v1/verify",
            body=body
        )
        response = self.identity_conection.send_request(http_request)
        return response["action_id"]

    def confirm_identity(self, action_id, confirmation_code, time_to_live=3600, count_to_live=1):
        # type: (str, str, int, int) -> str
        """Confirms the identity using confirmation code, that has been generated to confirm an identity.

        Args:
            action_id: The action identifier that was obtained on verification step.
            confirmation_code: The confirmation code that was recived on email box.
            time_to_live: The time to live.
            count_to_live: The count to live.
        Returns:
            A string that represent an identity validation token.
        """
        body = {
            "confirmation_code": confirmation_code,
            "action_id": action_id,
            "token": {"time_to_live": time_to_live, "count_to_live": count_to_live}
            }
        http_request = Request(
            method=Request.POST,
            endpoint="/v1/confirm",
            body=body
        )
        response = self.identity_conection.send_request(http_request)
        return response["validation_token"]

    def is_identity_valid(self, identity, identity_type, validation_token):
        # type: (str, str, str) -> bool
        """Check validation token
        Args:
            identity: The identity value.
            identity_type: The type of identity.
            validation_token: The validation token.
        Returns:
            Returns true if validation token is valid.
        """
        body = {
            "value": identity,
            "type": identity_type,
            "validation_token": validation_token
        }
        http_request = Request(
            method=Request.POST,
            endpoint="/v1/validate",
            body=body
        )
        response = self.identity_conection.send_request(http_request)
        if response == list():
            return True
        return False

    def validate_cards(self, cards):
        # type: (List[cards]) -> None
        """Validate cards signatures.
        Args:
            cards: list of cards to validate.

        Raises:
            VirgilClient.InvalidCardException if some cards are not valid.
        """
        invalid_cards = [
            card for card in cards if not self.card_validator.is_valid(card)
        ]
        if len(invalid_cards) > 0:
            raise self.InvalidCardException(invalid_cards)

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
    def identity_conection(self):
        # type: () -> IdentityServiceConnection
        """Identity service connection used for verify and validation cards"""
        if not self._identity_connection:
            self._identity_connection = IdentityServiceConnection(
                self.access_token,
                self.identity_service_url
            )
        return self._identity_connection

    @property
    def ra_connection(self):
        # type: () -> RaServiceConnection
        """Registration authority service connection used for """
        if not self._ra_connection:
            self._ra_connection = RaServiceConnection(
                self.access_token,
                self.ra_service_url
            )
        return self._ra_connection

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
    def card_validator(self):
        # type: () -> CardValidator
        """Card validator."""
        return self._card_validator

    @card_validator.setter
    def card_validator(self, validator):
        # type: (CardValidator) -> CardValidator
        """Set Card validator."""
        self._card_validator = validator
