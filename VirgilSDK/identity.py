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

from VirgilSDK.api import *
from VirgilSDK.helper import *


class Identity(VirgilClient):
    # Initiates the process to verify the identity
    # type - string, identity type 'email' or 'application'
    # value - string, identity value 'example@mail.com
    def verify(self, type, value):
        endpoint = '/verify'
        values = {'type': type,
                  'value': value}
        return Helper.json_loads(self._api_request('POST', endpoint, None, values))

    # Confirms the identity from verify step to obtain confirmation token
    # confirm_code - string, code obtained from verify step
    # action_id - string, id returned as verify response
    # count_to_live - int, count to live for token
    def confirm(self, confirm_code, action_id, count_to_live):
        endpoint = '/confirm'
        token = {'time_to_live': 3600, 'count_to_live': count_to_live}
        values = {'confirmation_code': confirm_code,
                  'action_id': action_id,
                  'token': token}
        return Helper.json_loads(self._api_request('POST', endpoint, None, values))

    # Validates the passed token
    # type - string, identity type 'email' or 'application'
    # value - string, identity value 'example@mail.com
    # valid_token - string, token obtained from confirmation step
    def validate(self, type, value, valid_token):
        endpoint = '/validate'
        values = {'type': type,
                  'value': value,
                  'validation_token': valid_token}
        return json.loads(self._api_request('POST', endpoint, None, values))
