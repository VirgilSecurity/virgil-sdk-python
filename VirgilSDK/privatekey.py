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

from VirgilSDK import identity, virgilcard
from VirgilSDK.virgil_crypto.cryptolib import *
from VirgilSDK.helper import *
from VirgilSDK.api import *


class PrivateKey(VirgilClient):
    # Load a private key into the private keys service storage
    # recipient_pub_key - string, base64 encoded private key service's public key
    # recipient_id - string, private key service's virgil card id
    # private_key - string, base64 encoded private key
    # virgil_card_id - string, id of the card related with private key
    # private_key_password - string, password for private key decryption
    def load_private_key(self, recipient_pub_key, recipient_id, private_key, virgil_card_id, private_key_password):
        endpoint = '/private-key'
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id}
        values = {'private_key': private_key,
                  'virgil_card_id': virgil_card_id}
        myvalues = Helper.json_dumps(values)
        encrypted_request = CryptoWrapper.encrypt(myvalues, str(recipient_id), recipient_pub_key)
        to_sign = request_id + myvalues
        signature = CryptoWrapper.sign(to_sign, private_key, private_key_password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        return self._api_request('POST', endpoint, headers, base64.b64encode(bytearray(encrypted_request)))

    # Get an existing private key
    # recipient_pub_key - string, base64 encoded private key service's public key
    # recipient_id - string, private key service's virgil card id
    # type - string, identity's type 'email' or 'application'
    # value - string, identity's value 'example@mail.com'
    # validation_token - string, base64 encoded token obtained from identity service
    # response_password - string, password to decrypt service response
    # virgil_card_id - string, id of card related with private key
    def grab_private_key(self, recipient_pub_key, recipient_id, type, value, validation_token, response_password, virgil_card_id):
        endpoint = '/private-key/actions/grab'
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token}
        identity = {"type": type,
                    'value': value,
                    'validation_token': validation_token}
        values = {'identity': identity,
                  'response_password': response_password,
                  'virgil_card_id': virgil_card_id}
        myvalues = Helper.json_dumps(values)
        encrypted_request = CryptoWrapper.encrypt(myvalues, str(recipient_id), recipient_pub_key)
        encrypted_response = self._api_request('POST', endpoint, headers, base64.b64encode(bytearray(encrypted_request)))
        try:
            return Helper.json_loads(str(bytearray(CryptoWrapper.decrypt_with_password(encrypted_response, response_password))))
        except ValueError:
            return encrypted_response

    # Delete a private key
    # recipient_pub_key - string, base64 encoded private key service's public key
    # recipient_id - string, private key service's virgil card id
    # private_key - string, base64 encoded private key
    # virgil_card_id - string, id of the card related with private key
    # private_key_password - string, password for private key decryption
    def delete_private_key(self, recipient_pub_key, recipient_id, private_key, virgil_card_id, private_key_password):
        endpoint = '/private-key/actions/delete'
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id}
        values = {'virgil_card_id': virgil_card_id}
        myvalues = Helper.json_dumps(values)
        encrypted_request = CryptoWrapper.encrypt(myvalues, str(recipient_id), recipient_pub_key)
        to_sign = request_id + myvalues
        signature = CryptoWrapper.sign(to_sign, private_key, private_key_password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        return self._api_request('POST', endpoint, headers, base64.b64encode(bytearray(encrypted_request)))
