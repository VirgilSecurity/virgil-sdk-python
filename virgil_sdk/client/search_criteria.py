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
from virgil_sdk.client.card import Card

class SearchCriteria(object):
    """Class holds criteria for searching Cards."""

    def __init__(self, identities, identity_type=None, scope=None):
        # type: (List[str], Optional[str], Optional[str]) -> None
        """Construct new SearchCriteria object."""
        self.identities = identities
        self.identity_type = identity_type
        self.scope = scope

    @classmethod
    def by_identity(cls, identity):
        # type: (str) -> SearchCriteria
        """Create new search criteria for searching cards by identity.

        Args:
            identity: Identity value.

        Returns:
            Search criteria with provided identity.
        """
        return cls.by_identities([identity])

    @classmethod
    def by_identities(cls, identities):
        # type: (List[str]) -> SearchCriteria
        """Create new search criteria for searching cards by identities.

        Args:
            identities: Identities value.

        Returns:
            Search criteria with provided identities.
        """
        return cls(
            identities=identities,
            scope=Card.Scope.APPLICATION
        )

    @classmethod
    def by_app_bundle(cls, bundle):
        # type: (str) -> SearchCriteria
        """Create new search criteria for searching cards by application bundle.

        Args:
            bundle: Application bundle.

        Returns:
            Search criteria for searching by bundle.
        """
        return cls(
            identities=[bundle],
            identity_type="application",
            scope=Card.Scope.GLOBAL
        )
