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
import datetime
import sys

from virgil_sdk.jwt.token_context import TokenContext
from virgil_sdk.cards.raw_card_content import RawCardContent
from virgil_sdk.client import RawSignedModel, ExpiredAuthorizationClientException
from virgil_sdk.utils import Utils
from virgil_sdk.verification import CardVerificationException
from .card import Card
from virgil_sdk.verification.virgil_card_verifier import VirgilCardVerifier
from virgil_sdk.client.card_client import CardClient
from virgil_sdk.signers.model_signer import ModelSigner

if sys.version_info[0] == 3 and sys.version_info[1] != 4:
    from json import JSONDecodeError
else:
    class JSONDecodeError(Exception):
        pass


class CardManager(object):
    """The CardsManager class provides a list of methods to manage the VirgilCard entities."""

    def __init__(
        self,
        card_crypto,
        access_token_provider,
        card_verifier,
        sign_callback=None,
        api_url="https://api.virgilsecurity.com",
        retry_on_unauthorized=False
    ):
        self._card_crypto = card_crypto
        self._model_signer = None
        self._card_client = None
        self._card_verifier = card_verifier
        self._sign_callback = sign_callback
        self._access_token_provider = access_token_provider
        self.__retry_on_unauthorized = retry_on_unauthorized
        self.__api_url = api_url

    def generate_raw_card(self, private_key, public_key, identity, previous_card_id="", extra_fields=None):
        # type: (PrivateKey, PublicKey, str, Optional[str], Optional[dict]) -> RawSignedModel
        """

        Args:
            private_key: PrivateKey for generate self signature.
            public_key: Card Public key.
            identity: Unique identity value.
            previous_card_id: Previous card id that current card is used to override to.
            extra_fields: The additional data associated with the card.

        Returns:
            The instance of newly published Card.
        """
        current_time = Utils.to_timestamp(datetime.datetime.utcnow())
        raw_card = RawSignedModel.generate(public_key, identity, current_time, previous_card_id)
        self.model_signer.self_sign(raw_card, private_key, extra_fields=extra_fields)
        return raw_card

    def publish_card(self, *args, **kwargs):
        # type: (...) -> Card
        """
        Publish a new Card using specified params.

        Args:
            *args:
                raw_card: Unpublished raw signed model.
                or
                private_key: PrivateKey for generate self signature.
                public_key: Card Public key.
                identity: Unique identity value.
                previous_card_id: Previous card id that current card is used to override to.
                extra_fields: The additional data associated with the card.
            **kwargs:
                raw_card: Unpublished raw signed model.
                or
                private_key: PrivateKey for generate self signature.
                public_key: Card Public key.
                identity: Unique identity value.
                previous_card_id: Previous card id that current card is used to override to.
                extra_fields: The additional data associated with the card.

        Returns:
            The instance of newly published Card.
        """
        if len(args) == 1 and isinstance(args[0], RawSignedModel):
            return self.__publish_raw_card(*args)
        elif len(kwargs.keys()) == 1 and "raw_card" in kwargs.keys():
            return self.__publish_raw_card(**kwargs)
        else:
            raw_card = self.generate_raw_card(*args, **kwargs)
            raw_published_card = self.__publish_raw_card(raw_card)
            return Card.from_signed_model(self._card_crypto, raw_published_card)

    def get_card(self, card_id):
        # type: (str) -> Card
        """
        Gets the card by specified ID.

        Args:
            card_id: The card ID to be found.

        Returns:
            The instance of found Card
        """
        token_context = TokenContext(None, "get")
        access_token = self._access_token_provider.get_token(token_context)
        raw_card, is_outdated = self.__try_execute(self.card_client.get_card, card_id, access_token, token_context)
        card = Card.from_signed_model(self._card_crypto, raw_card, is_outdated)
        if card.id != card_id:
            raise CardVerificationException("Invalid card")
        self.__validate(card)
        return card

    def search_card(self, identity):
        # type: (Union[str, list]) -> List[Card]
        """
        Searches for cards by specified identity.

        Args:
            identity: The identity (or list of identity) to be found.

        Returns:
            The list of found Card.
        """
        if not identity:
            raise ValueError("Missing identity for search")
        token_context = TokenContext(None, "search")
        access_token = self._access_token_provider.get_token(token_context)
        raw_cards = self.__try_execute(self.card_client.search_card, identity, access_token, token_context)
        cards = list(map(lambda x: Card.from_signed_model(self._card_crypto, x), raw_cards))
        if isinstance(identity, list):
            if any(list(map(lambda x: x.identity not in identity, cards))):
                raise CardVerificationException("Invalid cards")
        else:
            if any(list(map(lambda x: x.identity != identity, cards))):
                raise CardVerificationException("Invalid cards")
        for card in cards:
            self.__validate(card)
        return self._linked_card_list(cards)

    def import_card(self, card_to_import):
        # type: (Union[str, dict, RawSignedModel]) -> Card
        """
        Imports and verifies Card.

        Args:
            card_to_import: Exported data of signed model.

        Returns:
            Imported and verified card.
        """
        if isinstance(card_to_import, str) or Utils.check_unicode(card_to_import):
            card_to_import = str(card_to_import)
            try:
                if isinstance(Utils.json_loads(card_to_import), dict):
                    card = Card.from_signed_model(self._card_crypto, RawSignedModel.from_json(card_to_import))
                else:
                    raise JSONDecodeError
            except (JSONDecodeError, ValueError) as e:
                card = Card.from_signed_model(self._card_crypto, RawSignedModel.from_string(card_to_import))
        elif isinstance(card_to_import, dict) or isinstance(card_to_import, bytes):
            card = Card.from_signed_model(self._card_crypto, RawSignedModel.from_json(card_to_import))
        elif isinstance(card_to_import, RawSignedModel):
            card = Card.from_signed_model(self._card_crypto, card_to_import)
        elif card_to_import is None:
            raise ValueError("Missing card to import")
        else:
            raise TypeError("Unexpected type for card import")
        self.__validate(card)
        return card

    def export_card_to_string(self, card):
        # type: (Card) -> str
        """
        Exports the specified card as a BASE64 string.

        Args:
            card: Card instance to be exported.

        Returns:
            Serialize card to base64.
        """
        return self.export_card_to_raw_card(card).to_string()

    def export_card_to_json(self, card):
        # type: (Card) -> str
        """
        Exports the specified card as a json.

        Args:
            card: Card instance to be exported.

        Returns:
            Serialize card to json.
        """
        return self.export_card_to_raw_card(card).to_json()

    def export_card_to_raw_card(self, card):
        # type: (Card) -> RawSignedModel
        """
        Exports the specified card as a RawSignedModel.

        Args:
            card: Card instance to be exported.

        Returns:
            Returns instance of RawSignedModel representing Card.
        """
        raw_signed_model = RawSignedModel(card.content_snapshot)
        for signature in card.signatures:
            raw_signed_model.add_signature(signature)
        return raw_signed_model

    def __publish_raw_card(self, raw_card):
        # type: (RawSignedModel) -> Card
        if self._sign_callback:
            self._sign_callback(raw_card)
        card_content = RawCardContent.from_signed_model(self._card_crypto, raw_card)
        token_context = TokenContext(card_content.identity, "publish_card")
        token = self._access_token_provider.get_token(token_context)
        published_model = self.__try_execute(self.card_client.publish_card, raw_card, token, token_context)
        if published_model.content_snapshot != raw_card.content_snapshot:
            raise CardVerificationException("Publishing returns invalid card")
        card = Card.from_signed_model(self._card_crypto, published_model)
        self.__validate(card)
        return card

    def __validate(self, card):
        # type: (Card) -> None
        if card is None:
            raise ValueError("Missing card for validation")
        if not self.card_verifier.verify_card(card):
            raise CardVerificationException("Card verification failed!")

    def __try_execute(self, card_function, card_arg, token, context):
        # type: (function, Any, str, TokenContext) -> Any
        attempts_number = 2 if self.__retry_on_unauthorized else 1
        result = None
        while attempts_number > 0:
            try:
                result = card_function(card_arg, token)
            except ExpiredAuthorizationClientException as e:
                token = self._access_token_provider.get_token(context)
                if attempts_number-1 < 1:
                    raise e
            attempts_number -= 1
        return result

    @staticmethod
    def _linked_card_list(card_list):
        # type: (List[Card]) -> List[Card]
        unsorted = dict(map(lambda x: (x.id, x), card_list))
        for card in card_list:
            if card.previous_card_id:
                if card.previous_card_id in unsorted.keys():
                    unsorted[card.previous_card_id].is_outdated = True
                    card.previous_card = unsorted[card.previous_card_id]
                    del unsorted[card.previous_card_id]
        return list(unsorted.values())

    @property
    def model_signer(self):
        """
        Card signer.

        Returns:
            Returns instance of ModelSigner witch provides sign operations.
        """
        if not self._model_signer:
            self._model_signer = ModelSigner(self._card_crypto)
        return self._model_signer

    @property
    def card_client(self):
        """
        Card service client.

        Returns:
            Returns an instance of CardClient with provides card service operations.
        """
        if not self._card_client:
            if self.__api_url:
                self._card_client = CardClient(self.__api_url)
            else:
                self._card_client = CardClient()
        return self._card_client

    @card_client.setter
    def card_client(self, card_client):
        self._card_client = card_client

    @property
    def card_verifier(self):
        """
        Card verifier.

        Returns:
            Returns an instance of CardVerifier which provides card verification.
        """
        if not self._card_verifier:
            self._card_verifier = VirgilCardVerifier(self._card_crypto)
        return self._card_verifier
