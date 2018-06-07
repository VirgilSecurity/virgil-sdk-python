# Copyright (C) 2016-2018 Virgil Security Inc.
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
import json

from .base_card_client import BaseCardClient
from .connections.request import Request
from .connections.service_connection import ServiceConnection


class CardClient(BaseCardClient):

    def __init__(
        self,
        api_url="https://api.virgilsecurity.com",
        connection=None
    ):
        self._connection = connection
        self._api_url = api_url

    def publish_card(self, raw_card, token):
        # type: (RawSignedModel, str) -> RawSignedModel
        if not raw_card:
            raise ValueError("Missing raw card")

        if not token:
            raise ValueError("Missing JWT token")

        request = Request(
            "/card/v5",
            raw_card.content_snapshot,
            method=Request.POST
        )

        request.authorization(token)

        response = self.__connection.send(request)

        return json.loads(response)

    def search_card(self, identity, token):
        # type: (str, str) -> List[RawSignedModel]
        if not identity:
            raise ValueError("Missing identity")

        if not token:
            raise ValueError("Missing JWT token")

        request = Request(
            "/card/v5/actions/search",
            json.dumps({"Identity": identity}),
            Request.POST,
        )

        request.authorization(token)

        response = self.__connection.send(request)

        cards = self.__parse_cards_from_response(response)

        return cards

    def get_card(self, card_id, token):
        # type: (str, str) -> Tuple[RawSignedModel, bool]
        if not card_id:
            raise ValueError("Missing card id")

        if not token:
            raise ValueError("Missing access token")

        request = Request(
            "/card/v5/{}".format(card_id),
        )

        request.authorization(token)

        response = self.__connection.send(request)

        card_raw = json.loads(response)

        superseded = False
        if response.headers and "X-Virgil-Is-Superseeded" in response.headers.keys():
            if response.headers["X-Virgil-Is-Superseeded"]:
                superseded = True

        return card_raw, superseded

    @property
    def api_url(self):
        if not self._api_url:
            self._api_url = "https://api.virgilsecurity.com"
        return self._api_url

    def __parse_cards_from_response(self, response):
        pass

    @property
    def __connection(self):
        if self._connection is None:
            self._connection = ServiceConnection(self.api_url)
        return self._connection
