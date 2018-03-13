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


class CardManager(object):
    """The CardsManager class provides a list of methods to manage the VirgilCard entities."""

    def __init__(
        self,
        card_crypto,
        access_token_provider,
        card_verifier,
        sign_callback,
        api_url=None,
    ):
        self._card_crypto = card_crypto
        self._model_signer = None
        self._card_client = None
        self._card_verifier = card_verifier
        self._sign_callback = sign_callback
        self._access_token_provider = access_token_provider
        self.__api_url = api_url

    @property
    def model_signer(self):
        if not self._model_signer:
            self._model_signer = ModelSigner(self._card_crypto)
        return self._model_signer

    @property
    def card_client(self):
        if not self._card_client:
            if self.__api_url:
                self._card_client = CardClient(self.__api_url)
            else:
                self._card_client = CardClient()
        return self._card_client

    @card_client.setter
    def card_client(self, card_client):
        self._card_client = card_client
