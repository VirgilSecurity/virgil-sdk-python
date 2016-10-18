from virgil_sdk.client.requests.signable_request import SignableRequest
from virgil_sdk.client.utils import Utils
from virgil_sdk.client.card import Card

class CreateCardRequest(SignableRequest):
    def __init__(self,
                 identity,
                 identity_type,
                 raw_public_key,
                 data=None,
                 info=None):
        super(CreateCardRequest, self).__init__()
        self.identity = identity
        self.identity_type = identity_type
        self.public_key = raw_public_key
        self.data = data
        self.info = info

    def restore_from_snapshot_model(self, snapshot_model):
        self.identity = snapshot_model['identity']
        self.identity_type = snapshot_model['identity_type']
        self.public_key = snapshot_model['public_key']
        self.data = snapshot_model.get('data', {})
        self.info = snapshot_model['info']

    def snapshot_model(self):
        return {
            'identity': self.identity,
            'identity_type': self.identity_type,
            'public_key': Utils.b64encode(self.public_key),
            'scope': Card.Scope.APPLICATION,
            'data': self.data,
            'info': self.info
        }
