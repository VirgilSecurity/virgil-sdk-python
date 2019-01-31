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

from virgil_sdk import __version__
from virgil_sdk.client import RawSignedModel
from virgil_sdk.client.connections.virgil_agent_adapter import VirgilAgentAdapter
from virgil_sdk.utils import Utils
from .base_card_client import BaseCardClient
from .connections.request import Request
from .connections.service_connection import ServiceConnection


class CardClient(BaseCardClient):
    """
    The CardClient class provides operations with Virgil Cards service.
    """

    def __init__(
        self,
        api_url="https://api.virgilsecurity.com",  # type: str
        connection=None  # type: ServiceConnection
    ):
        self._api_url = api_url
        self.__connection = connection or ServiceConnection(
            self.api_url,
            adapters=[VirgilAgentAdapter("sdk", __version__)]
        )

    def publish_card(self, raw_card, token):
        # type: (RawSignedModel, str) -> RawSignedModel
        """
        Publishes card in Virgil Cards service.

        Args:
            raw_card: An instance of RawSignedModel class.
            token: The string representation of Jwt token.

        Returns:
            Published raw card.
        """
        if not raw_card:
            raise ValueError("Missing raw card")

        if not token:
            raise ValueError("Missing JWT token")

        request = Request(
            "/card/v5",
            Utils.json_loads(raw_card.to_json()),
            method=Request.POST
        )

        request.authorization(token)
        response, headers = self.__connection.send(request)
        return RawSignedModel(**response)

    def search_card(self, identity, token):
        # type: (Union[str, list], str) -> List[RawSignedModel]
        """
        Searches a cards on Virgil Services by specified identity.

        Args:
            identity: The identity (or list of identity).
            token: The string representation of Jwt token.

        Returns:
           A list of found cards in raw form.
        """
        if not identity:
            raise ValueError("Missing identity")

        if not token:
            raise ValueError("Missing JWT token")

        if isinstance(identity, str) or Utils.check_unicode(identity):
            request_body = {"identity": identity}
        elif isinstance(identity, list):
            request_body = {"identities": identity}
        else:
            raise ValueError("Wrong identity(ies) type")

        request = Request(
            "/card/v5/actions/search",
            request_body,
            Request.POST,
        )

        request.authorization(token)

        response, headers = self.__connection.send(request)
        cards = self.__parse_cards_from_response(response)

        return cards

    def get_card(self, card_id, token):
        # type: (str, str) -> Tuple[RawSignedModel, bool]
        """
        Gets a card from Virgil Services by specified card ID.

        Args:
            card_id: The Card ID.
            token: The string representation of Jwt token.

        Returns:
            An instance of RawSignedModel class and flag,
            which determines whether or not this raw card is superseded.

        Raises:
            ValueError: Missed argument.
        """
        if not card_id:
            raise ValueError("Missing card id")

        if not token:
            raise ValueError("Missing access token")

        request = Request(
            "/card/v5/{}".format(card_id),
        )

        request.authorization(token)

        response, headers = self.__connection.send(request)

        card_raw = RawSignedModel(**response)

        superseded = False
        if headers and "X-VIRGIL-IS-SUPERSEEDED" in headers.keys():
            if headers["X-VIRGIL-IS-SUPERSEEDED"]:
                superseded = True

        return card_raw, superseded

    @property
    def api_url(self):
        """
        Get service url.
        """
        return self._api_url

    def __parse_cards_from_response(self, response):
        if response:
            result = list()
            for card in response:
                result.append(RawSignedModel(**card))
            return result
        else:
            return response
