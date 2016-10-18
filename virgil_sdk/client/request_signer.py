class RequestSigner(object):
    def __init__(self, crypto):
        self.crypto = crypto

    def self_sign(self, signable_request, private_key):
        fingerprint = self.crypto.calculate_fingerprint(
            signable_request.snapshot
        )
        signature = self.crypto.sign(
            fingerprint.value,
            private_key
        )

        signable_request.sign_with(
            fingerprint.to_hex,
            signature
        )

    def authority_sign(self, signable_request, signer_id, private_key):
        fingerprint = self.crypto.calculate_fingerprint(
            signable_request.snapshot
        )
        signature = self.crypto.sign(
            fingerprint.value,
            private_key
        )

        signable_request.sign_with(
            signer_id,
            signature
        )
