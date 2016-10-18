import json
from virgil_sdk.cryptography.crypto import VirgilCrypto
from virgil_sdk.client.utils import Utils

class SignableRequest(object):
    def __init__(self):
        self._snapshot = None
        self._signatures = {}

    def snapshot_model(self):
        raise NotImplementedError()

    def restore_from_snapshot_model(self, snapshot):
        raise NotImplementedError()

    def restore(self, snapshot, signatures):
        self._snapshot = snapshot
        self._signatures = signatures

        model = json.loads(bytearray(snapshot).decode())
        self.restore_from_snapshot_model(model)

    def take_snapshot(self):
        json_string = json.dumps(self.snapshot_model())
        snapshot = VirgilCrypto.strtobytes(json_string)
        return snapshot

    def export(self):
        request_model = self.request_model
        json_string = json.dumps(request_model)
        return Utils.b64encode(json_string)

    def sign_with(self, fingerprint_id, signature):
        self.signatures[fingerprint_id] = Utils.b64encode(signature)

    @property
    def request_model(self):
        return {
            'content_snapshot': Utils.b64encode(self.snapshot),
            'meta': {
                'signs': self.signatures
            }
        }

    @property
    def snapshot(self):
        if not self._snapshot:
            self._snapshot = self.take_snapshot()
        return self._snapshot

    @property
    def signatures(self):
        return self._signatures
