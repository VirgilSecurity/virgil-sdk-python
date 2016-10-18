from virgil_sdk.client.card import Card

class SearchCriteria(object):
    def __init__(self, identities, identity_type=None, scope=None):
        self.identities = identities
        self.identity_type = identity_type
        self.scope = scope

    @classmethod
    def by_identity(cls, identity):
        return cls.by_identities([identity])

    @classmethod
    def by_identities(cls, identities):
        return cls(
            identities=identities,
            scope=Card.Scope.APPLICATION
        )

    @classmethod
    def by_app_bundle(cls, bundle):
        return cls(
            identities=[bundle],
            identity_type="application",
            scope=Card.Scope.GLOBAL
        )
