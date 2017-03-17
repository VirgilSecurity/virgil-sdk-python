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
from virgil_sdk.api import VirgilBuffer
from virgil_sdk.api import VirgilCard
from virgil_sdk.client import Card
from virgil_sdk.client import SearchCriteria
from virgil_sdk.client import Utils
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import CreateGlobalCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.client.requests import RevokeGlobalCardRequest
from virgil_sdk.identities import IdentityEmail


class CardManager(object):
    """The CardsManager class provides a list of methods to manage the VirgilCard entities."""

    def __init__(self, context):
        self.context = context

    def create(self, identity, owner_key, custom_fields=None):
        # type: (Union[IdentityUser, IdentityApplication, IdentityEmail], VirgilKey, dict) -> VirgilCard
        """Creates a new VirgilCard that is representing user's Public key and information
        about identity. This card has to be published to the Virgil's services.
        Args:
            identity: The user's identity.
            owner_key: The owner's VirgilKey.
            custom_fields: The custom fields
        Returns:
            A new instance of VirgilCard class, that is representing user's Public key.
        """
        validation_token = None
        if isinstance(identity, IdentityEmail):
            if identity.is_confirmed():
                validation_token = identity.validation_token
            else:
                raise ValueError("Unconfirmed identity, please confirm before use.")
        card_model = self.__build_card_model(
            identity.value,
            identity.type,
            custom_fields,
            identity.scope,
            owner_key,
            validation_token
        )
        return VirgilCard(self.context, card_model)

    def find(self, identities, identity_type=None):
        # type: (List[str], Optional[str]) -> List[VirgilCard]
        """Finds a VirgilCard's by specified identities in application scope.
        Args:
            identities: The list of sought identities
            identity_type: Type of the identity.
        Returns:
            A List of found VirgilCard's.
        Raises:
            ValueError when identities list empty
        """
        if not identities:
            raise ValueError("Identities empty!")
        if identity_type:
            criteria = SearchCriteria(identities, identity_type, Card.Scope.APPLICATION)
            founded = self.context.client.search_cards_by_criteria(criteria)
        else:
            founded = self.context.client.search_cards_by_identities(identities)
        return list(map(lambda x: VirgilCard(self.context, x), founded))

    def find_global(self, identities, identity_type=None):
        # type: (List[str], Optional[str]) -> List[VirgilCard]
        """Finds VirgilCard's by specified identities and type in global scope.
        Args:
            identities: The list of sought identities
            identity_type: Type of the identity.
        Returns:
            A List of found VirgilCard's.
        Raises:
            ValueError when identities list empty
        """
        if not identities:
            raise ValueError("Identities empty!")
        criteria = SearchCriteria(identities, identity_type, Card.Scope.GLOBAL)
        founded = self.context.client.search_cards_by_criteria(criteria)
        return list(map(lambda x: VirgilCard(self.context, x), founded))

    def import_card(self, exported_card):
        # type: (str) -> VirgilCard
        """Imports a VirgilCard from specified buffer.
        Args:
            exported_card: A Card in string representation.
        Returns:
            An instance of VirgilCard.
        """
        buffer = VirgilBuffer.from_string(exported_card, "base64")
        imported_card_model = Utils.json_loads(buffer.get_bytearray())
        card = Card.from_response(imported_card_model)
        return VirgilCard(self.context, card)

    @staticmethod
    def publish(card):
        # type: (VirgilCard) -> None
        """Publishes a VirgilCard into global Virgil Services scope.
        Args:
            card: The Card to be published.
        """
        card.publish()

    def revoke(self, card):
        # type: (VirgilCard) -> None
        """Revokes a VirgilCard from Virgil Services.
        Args:
            card: The card to be revoked.
        """
        revoke_card_request = RevokeCardRequest(card.id, RevokeCardRequest.Reasons.Unspecified)
        app_key = self.context.credentials.get_app_key(self.context.crypto)

        snapshot_fingerprint = self.context.crypto.calculate_fingerprint(revoke_card_request.snapshot)
        signature = VirgilBuffer(
            self.context.crypto.sign(snapshot_fingerprint.value, app_key)
        ).to_string("base64")

        revoke_card_request.signatures = {self.context.credentials.app_id: signature}
        self.context.client.revoke_card_from_request(revoke_card_request)

    def revoke_global(self, card, key, identity):
        # type: (VirgilCard, VirgilKey, Union[IdentityUser, IdentityApplication, IdentityEmail]) -> None
        """Revokes a global VirgilCard from Virgil Security services.
        Args:
            card: The Card to be revoked.
            key: The Key associated with the revoking Card.
            identity_token: The identity token.
        """
        revoke_global_card_request = RevokeGlobalCardRequest(
            card.id,
            identity.validation_token,
            RevokeGlobalCardRequest.Reasons.Unspecified
        )
        snapshot_fingerprint = self.context.crypto.calculate_fingerprint(revoke_global_card_request.snapshot)
        revoke_global_card_request.signatures = {
            card.id: key.sign(VirgilBuffer(snapshot_fingerprint.value)).to_string("base64")
        }
        self.context.client.revoke_global_card_from_request(revoke_global_card_request)

    def get(self, card_id):
        # type: (str) -> VirgilCard
        """Gets a VirgilCard from Virgil Security services by specified Card ID.
        Args:
            card_id: is a unique string that identifies the Card
        within Virgil Security services.
        Returns:
            An instance of VirgilCard class.
        """
        card_model = self.context.client.get_card(card_id)
        return VirgilCard(self.context, card_model)

    def __build_card_model(self, identity, identity_type, custom_fields, scope, owner_key, validation_token=None):
        # type: (str, str, dict, Card.Scope, VirgilKey) -> Card
        """Constructs the card model
        Args:
            identity: The user's identity.
            identity_type: Type of the identity.
            custom_fields: The custom fields (optional).
            scope: Card scope
            owner_key: The owner's VirgilKey.
        Returns:
            Card model for VirgilCard creation.
        Raises:
            ValueError when scope incorrect.
        """
        card_config = {
            'identity': identity,
            'identity_type': identity_type,
            'public_key': owner_key.export_public_key().get_bytearray(),
            'data': custom_fields,
        }
        card_model = Card(**card_config)
        if scope == Card.Scope.APPLICATION:
            card_request = CreateCardRequest(**card_config)
        elif scope == Card.Scope.GLOBAL:
            card_config.update({"validation_token": validation_token})
            card_request = CreateGlobalCardRequest(**card_config)
        else:
            raise ValueError("Unknown scope value")
        card_model.snapshot = card_request.snapshot
        snapshot_fingerprint = self.context.crypto.calculate_fingerprint(card_model.snapshot)
        card_model.scope = scope
        card_model.id = snapshot_fingerprint.to_hex
        self_signature = owner_key.sign(VirgilBuffer(snapshot_fingerprint.value))
        card_model.signatures = {card_model.id: self_signature.to_string("base64")}
        return card_model
