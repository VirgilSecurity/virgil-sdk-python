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
from virgil_sdk.client import Card
from virgil_sdk.identities import Identity


class IdentityEmail(Identity):

    def __init__(
            self,
            context,  # type: VirgilContext
            value,  # type: str
    ):
        super(IdentityEmail, self).__init__(context, value, "email")
        self.__action_id = None
        self._validation_token = None
        self.scope = Card.Scope.GLOBAL

    def check(self):
        # type: () -> None
        """Initiates an identification process for current identity"""
        self.__action_id = self._context.client.verify_identity(self.value, self.type)

    def confirm(self, confirmation_code):
        # type: (str) -> None
        """Second part of identification process - confirmation
        Args:
            confirmation_code: The confirmation code sended to client email.
        """
        self._validation_token = self._context.client.confirm_identity(self.__action_id, confirmation_code)

    def is_confirmed(self):
        # type: () -> bool
        """Check the user has passed the identification
        Returns:
            Status of identification process
        """
        if self.validation_token:
            return True
        return False

    @property
    def validation_token(self):
        # type: () -> str
        """Validation token getter"""
        return self._validation_token
