from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.client.http import Request
from virgil_sdk.client.http import CardsServiceConnection
from virgil_sdk.client import RequestSigner
from virgil_sdk.client import SearchCriteria
from virgil_sdk.client import Card

class VirgilClient(object):
    def __init__(self, access_token, app_id, app_key):
        self.access_token = access_token
        self.app_id = app_id
        self.app_key = app_key
        self.cards_service_url = "https://cards.virgilsecurity.com"
        self.cards_read_only_service_url = "https://cards-ro.virgilsecurity.com"
        self._crypto = None
        self._cards_connection = None
        self._read_cards_connection = None
        self._request_signer = None

    def create_card(self, identity, identity_type, key_pair):
        request = CreateCardRequest(
            identity=identity,
            identity_type=identity_type,
            raw_public_key=self.crypto.export_public_key(key_pair.public_key),
        )
        self.request_signer.self_sign(request, key_pair.private_key)
        self.request_signer.authority_sign(request, self.app_id, self.app_key)

        return self.create_card_from_signed_request(request)

    def create_card_from_signed_request(self, create_request):
        http_request = Request(
            method=Request.POST,
            endpoint="/v4/card",
            body=create_request.request_model
        )
        raw_response = self.cards_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        return card

    def revoke_card(self, card_id, reason=RevokeCardRequest.Reasons.Unspecified):
        request = RevokeCardRequest(
            card_id=card_id,
            reason=reason,
        )
        self.request_signer.authority_sign(request, self.app_id, self.app_key)

        return self.revoke_card_from_signed_request(request)

    def revoke_card_from_signed_request(self, revocation_request):
        http_request = Request(
            method=Request.DELETE,
            endpoint="/v4/card/%s" % revocation_request.card_id,
            body=revocation_request.request_model
        )
        self.cards_connection.send_request(http_request)

    def get_card(self, card_id):
        http_request = Request(
            method=Request.GET,
            endpoint="/v4/card/%s" % card_id,
        )
        raw_response = self.read_cards_connection.send_request(http_request)
        card = Card.from_response(raw_response)
        return card

    def search_cards_by_identities(self, *identities):
        return self.search_cards_by_criteria(
            SearchCriteria.by_identities(identities)
        )

    def search_cards_by_app_bundle(self, bundle):
        return self.search_cards_by_criteria(
            SearchCriteria.by_app_bundle(bundle)
        )

    def search_cards_by_criteria(self, search_criteria):
        body = {"identities": search_criteria.identities}
        if search_criteria.identity_type:
            body["identity_type"] = search_criteria.identity_type
        if search_criteria.scope == Card.Scope.GLOBAL:
            body["scope"] = Card.Scope.GLOBAL
        http_request = Request(
            method=Request.POST,
            endpoint="/v4/card/actions/search",
            body=body,
        )
        response = self.read_cards_connection.send_request(http_request)
        cards = [Card.from_response(card) for card in response]
        return cards

    @property
    def cards_connection(self):
        if not self._cards_connection:
            self._cards_connection = CardsServiceConnection(
                self.access_token,
                self.cards_service_url
            )
        return self._cards_connection

    @property
    def read_cards_connection(self):
        if not self._read_cards_connection:
            self._read_cards_connection = CardsServiceConnection(
                self.access_token,
                self.cards_read_only_service_url
            )
        return self._read_cards_connection

    @property
    def request_signer(self):
        if not self._request_signer:
            self._request_signer = RequestSigner(self.crypto)
        return self._request_signer

    @property
    def crypto(self):
        if not self._crypto:
            self._crypto = VirgilCrypto()
        return self._crypto

    @staticmethod
    def extract_raw_key_from(key):
        return key.value if hasattr(key, "value") else key

