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

from virgil_crypto import VirgilCrypto
from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_crypto.card_crypto import CardCrypto
from virgil_sdk import VirgilCardVerifier, CardManager
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.utils import Utils
from virgil_sdk.jwt.providers import CallbackJwtProvider


############# SERVER SIDE ####################


class UserStorage(object):
    """Simple authentication storage"""

    def __init__(self, authenticated_user=""):
        self.authenticated_user = authenticated_user


user_storage = UserStorage()


def authenticated_query_to_server(token_context, token_ttl=300):
    """Sample example of how server issues token"""
    crypto = VirgilCrypto()

    # Account data from dashboard
    api_private_key = ""  # FILL THIS FIELD
    app_id = ""  # FILL THIS FIELD
    api_key_id = ""  # FILL THIS FIELD

    # Loading key for next usage
    imported_api_private_key = crypto.import_private_key(Utils.b64decode(api_private_key))

    # Instantiate token generator
    builder = JwtGenerator(
        app_id,
        imported_api_private_key,
        api_key_id,
        token_ttl,
        AccessTokenSigner()
    )

    identity = user_storage.authenticated_user
    token = builder.generate_token(identity).to_string()
    print(token)  # print generated jwt token
    return token


############# CLIENT SIDE ####################


def get_token_from_server(token_context):
    """
    Get generated token from server-side

    This call on your service must be under authorization!
    """
    jwt_from_server = authenticated_query_to_server(token_context)
    return jwt_from_server


def authenticate_on_server(username):
    """Do call of your service authentication """
    user_storage.authenticated_user = username


if __name__ == '__main__':

    # Prepare for Card Manager initialize
    crypto = VirgilCrypto()
    card_crypto = CardCrypto()
    validator = VirgilCardVerifier(card_crypto)
    token_provider = CallbackJwtProvider(get_token_from_server)

    # Basic card manager config
    card_manager = CardManager(
        card_crypto,
        access_token_provider=token_provider,
        card_verifier=validator
    )

    username = ""  # FILL THIS FIELD user identity from who we searching card
    identity_for_search = ""  # FILL THIS FIELD identity of user that we want to find

    authenticate_on_server(username)

    # Searching card
    found_cards = card_manager.search_card(identity_for_search)

    for card in found_cards:
        print(vars(card))  # print registered Virgil Card
