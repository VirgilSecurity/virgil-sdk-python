from virgil_sdk.client.requests.signable_request import SignableRequest

class RevokeCardRequest(SignableRequest):
    class Reasons(object):
        Unspecified = 'unspecified'
        Compromised = 'compromised'

    def __init__(self,
                 card_id,
                 reason=Reasons.Unspecified):
        super(RevokeCardRequest, self).__init__()
        self.card_id = card_id
        self.reason = reason

    def restore_from_snapshot_model(self, snapshot_model):
        self.card_id = snapshot_model['card_id']
        self.reason = snapshot_model['revocation_reason']

    def snapshot_model(self):
        return {
            'card_id': self.card_id,
            'revocation_reason': self.reason,
        }
