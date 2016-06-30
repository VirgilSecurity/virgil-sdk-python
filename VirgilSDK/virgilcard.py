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

from VirgilSDK import identity
from VirgilSDK.virgil_crypto.cryptolib import *
from VirgilSDK.helper import *
from VirgilSDK.api import *


class VirgilCard(VirgilClient):
    # Returns the information about the Public Key by the ID
    # key_id - string, public key ID
    # signed - bool, is request signed or not
    # signer_card_id - string, signer card id
    # private_key - string, base64 encoded private key of signer card
    # password - string, private key's password
    def get_public_key(self, key_id, signed=False, signer_card_id=None, private_key=None, password=None):
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token}
        if signed:
            request_id = Helper.generate_id()
            headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                       'X-VIRGIL-REQUEST-ID': request_id,
                       'X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID': signer_card_id}
            signature = CryptoWrapper.sign(request_id, private_key, password)
            headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        endpoint = '/public-key/' + key_id
        return Helper.json_loads(self._api_request('GET', endpoint, headers))

    # Revoke a Public Key endpoint
    # key_id - string, public key ID
    # identities - list, identitties of all virgil cards related with key
    # signer_card_id - string, signer card id
    # private_key - string, base64 encoded private key of signer card
    # password - string, private key's password
    def delete_public_key(self, key_id, identities, signer_card_id, private_key, password):
        endpoint = '/public-key/' + key_id
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id,
                   'X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID': signer_card_id}
        values = {'identities': identities}
        myvalues = Helper.json_dumps(values)
        toSign = request_id + myvalues
        signature = CryptoWrapper.sign(toSign, private_key, password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        return self._api_request('DELETE', endpoint, headers, values)

    # Creates a Virgil Card entity.
    # type - string, identity's type 'email' or 'application'
    # value - string, identity's value 'example@mail.com'
    # data - dictionary, additional data
    # validation_token - string, base64 encoded token obtained from identity service
    # private_key - string, base64 encoded encrypted private key of new Virgil card
    # private_key_password - string, privake key's password
    # public_key - string, in order to create new Public Key instance you should pass base64 encoded key parameter
    # public_key_id - string, in order to attach the Virgil Card to the existing Public Key you should pass key id
    # signs - dictionary, contains signature information
    def create_card(self, type, value, data, validation_token, private_key, private_key_password, public_key=None, public_key_id=None, signs=None):
        endpoint = '/virgil-card'
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id}
        identity = {"type": type,
                    'value': value,
                    'validation_token': validation_token}
        values = {'identity': identity,
                 'data': data}
        if public_key_id:
            values['public_key_id'] = public_key_id
        if public_key:
            values['public_key'] = public_key
        if signs:
            values['signs'] = signs
        myvalues = Helper.json_dumps(values)
        to_sign = request_id + myvalues
        signature = CryptoWrapper.sign(to_sign, private_key, private_key_password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        return Helper.json_loads(self._api_request('POST', endpoint, headers, values))

    # Performs the global search fot the applications' Virgil Cards
    # value - string, search parameter
    def search_app(self, value):
        endpoint = '/virgil-card/actions/search/app'
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token}
        values = {'value': value}
        return Helper.json_loads(self._api_request('POST', endpoint, headers, values))

    # Signs another Virgil Card addressed in the request
    # signed_card_id - string, ID of signed card
    # signer_card_id - string, ID of signer card
    # private_key - string, base64 encoded encrypted private key of signer Virgil card
    # private_key_password - string, privake key's password
    def sign_card(self, signed_card_id, signer_card_id, private_key, private_key_password):
        endpoint = '/virgil-card/' + signer_card_id + '/actions/sign'
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id,
                   'X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID': signer_card_id}
        card_info = self.get_virgil_card(signed_card_id)
        signed_dig = CryptoWrapper.sign(str(card_info["hash"]), private_key, private_key_password)
        values = {'signed_virgil_card_id': signed_card_id,
                  'signed_digest': base64.b64encode(bytearray(signed_dig)).decode()}
        myvalues = Helper.json_dumps(values)
        to_sign = request_id + myvalues
        signature = CryptoWrapper.sign(to_sign, private_key, private_key_password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        return Helper.json_loads(self._api_request('POST', endpoint, headers, values))

    # Removes the Sign of another Virgil Card
    # signed_card_id - string, ID of signed card
    # signer_card_id - string, ID of signer card
    # private_key - string, base64 encoded encrypted private key of signer Virgil card
    # private_key_password - string, privake key's password
    def unsign_card(self, signed_card_id, signer_card_id, private_key, private_key_password):
        endpoint = '/virgil-card/' + signer_card_id + '/actions/unsign'
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id,
                   'X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID': signer_card_id}
        values = {'signed_virgil_card_id': signed_card_id}
        myvalues = Helper.json_dumps(values)
        to_sign = request_id + myvalues
        signature = CryptoWrapper.sign(to_sign, private_key, private_key_password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        result =self._api_request('POST', endpoint, headers, values)
        if result == b'':
            return 'Unsigned!'
        else:
            return result

    # Revoke a Virgil Card endpoint.
    # type - string, identity's type 'email' or 'application'
    # value - string, identity's value 'example@mail.com'
    # validation_token - string, base64 encoded token obtained from identity service
    # virgil_card_id - string, id of deleted card
    # private_key - string, base64 encoded encrypted private key of deleted Virgil card
    # private_key_password - string, privake key's password
    def delete_card(self, type, value, validation_token, virgil_card_id, private_key, private_key_password):
        endpoint = '/virgil-card/' + virgil_card_id
        request_id = Helper.generate_id()
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token,
                   'X-VIRGIL-REQUEST-ID': request_id,
                   'X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID': virgil_card_id}
        identity = {"type": type, "value": value, "validation_token": validation_token}
        value = {'identity': identity}
        myvalues = Helper.json_dumps(value)
        to_sign = request_id + myvalues
        signature = CryptoWrapper.sign(to_sign, private_key, private_key_password)
        headers['X-VIRGIL-REQUEST-SIGN'] = base64.b64encode(bytearray(signature))
        return self._api_request('DELETE', endpoint, headers, value).decode()

    # Returns the information about the Virgil Card by the ID.
    # cardID - string, Virgil card ID
    def get_virgil_card(self, cardID):
        endpoint = '/virgil-card/'+cardID
        headers = {'X-VIRGIL-ACCESS-TOKEN': self.token}
        result = self._api_request('GET', endpoint, headers)
        json_res = Helper.json_loads(result)
        return json_res


   # Performs the search by search criterias
   # value - string, request parameter
   # type - string, request parameter
   # relation - list, request parameter
   # include_unconfirmed - string ('true' or 'false'), request parameter
   def search_card(self, value, type='email', relation=None, include_unauthorized=None):
       endpoint = '/virgil-card/actions/search'
       headers = {'X-VIRGIL-ACCESS-TOKEN': self.token}
       values = {'value': value}
       if type:
           values['type'] = type
       if relation:
           values['relation'] = relation
       if include_unauthorized:
           values['include_unauthorized'] = include_unauthorized
       return Helper.json_loads(self._api_request('POST', endpoint, headers, values))
       
    
   def search_global_card(self, value, type='email'):
       endpoint = '/virgil-card/actions/search'
       if type:
           endpoint += '/' + type
       headers = {'X-VIRGIL-ACCESS-TOKEN': self.token}
       values = {'value': value}
       return Helper.json_loads(self._api_request('POST', endpoint, headers, values))
