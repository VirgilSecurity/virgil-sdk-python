from virgil_sdk.client.utils import Utils

class Card(object):
    class Scope(object):
        APPLICATION = "application"
        GLOBAL = "global"

    def __init__(
            self,
            id,
            snapshot,
            identity,
            identity_type,
            public_key,
            scope,
            data,
            device,
            device_name,
            version,
            signatures):
        self.id = id
        self.snapshot = snapshot
        self.identity = identity
        self.identity_type = identity_type
        self.public_key = public_key
        self.scope = scope
        self.data = data or {}
        self.device = device
        self.device_name = device_name
        self.version = version
        self.signatures = signatures or {}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))

    def __str__(self):
        return "Cards {} {} {} {} {}".format(
            self.id,
            self.identity,
            self.identity_type,
            self.scope,
            self.public_key,
        )

    def __repr__(self):
        return str(self)

    @classmethod
    def from_response(cls, response):
        snapshot = Utils.b64decode(response["content_snapshot"])
        snapshot_model = Utils.json_loads(snapshot)
        info = snapshot_model.get("info", {}) or {}

        return cls(
            id=response["id"],
            snapshot=snapshot,
            identity=snapshot_model["identity"],
            identity_type=snapshot_model["identity_type"],
            public_key=tuple(bytearray(Utils.b64decode(snapshot_model["public_key"]))),
            device=info.get("device"),
            device_name=info.get("device_name"),
            data=snapshot_model.get("data", {}),
            scope=snapshot_model["scope"],
            version=response["meta"]["card_version"],
            signatures=response["meta"]["signs"]
        )
