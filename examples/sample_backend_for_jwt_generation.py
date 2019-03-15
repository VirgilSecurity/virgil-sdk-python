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

import json
import time
import os

from virgil_crypto import VirgilCrypto
from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.utils import Utils
from base64 import b64encode
from flask import Flask, request, Response, jsonify

app = Flask(__name__)

user_storage = dict()  # primitive user storage


def generate_jwt(identity):
    crypto = VirgilCrypto()

    # Account data from dashboard
    api_private_key = ""  # FILL THIS FIELD
    app_id = ""  # FILL THIS FIELD
    api_key_id = ""  # FILL THIS FIELD

    token_ttl = 10  # token time to live in seconds

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
    token = builder.generate_token(identity).to_string()  # generating token and transforming to string
    return token


@app.route('/authenticate', methods=['POST'])
def authenticate():
    resp = Response()

    loaded_data = json.loads(request.data)  # loading data from request
    if "identity" not in loaded_data.keys():
        resp.status_code = 400
        return resp

    identity = loaded_data["identity"]

    if identity:
        token = b64encode(os.urandom(32)).decode()  # generate sample token
        user_storage[token] = identity  # write user to user storage
        return jsonify({"auth_token": token})  # return our app authentication token
    else:
        resp.status_code = 400
        return resp


@app.route('/virgil-jwt', methods=['GET'])
def get_jwt():
    resp = Response()

    auth_header = request.headers.get("Authorization")  # check for authentication in request
    if not auth_header:
        resp.status_code = 401
        return resp

    auth_list = auth_header.split(" ")

    if len(auth_list) < 2 or "Bearer" != auth_list[0] or auth_list[1] not in user_storage.keys():
        resp.status_code = 401
        return resp

    virgil_jwt = generate_jwt(user_storage[auth_list[1]])  # generating jwt token
    return jsonify({"virgil_token": virgil_jwt})  # return jwt string


if __name__ == '__main__':
    app.run()
