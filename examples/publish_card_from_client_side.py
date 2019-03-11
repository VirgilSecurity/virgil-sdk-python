from virgil_crypto import VirgilCrypto
from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_crypto.card_crypto import CardCrypto
from virgil_sdk import VirgilCardVerifier, CardManager
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.utils import Utils
from virgil_sdk.jwt.providers import CallbackJwtProvider



############# SERVER SIDE ####################

# Sample example of how server issues token
def authenticated_query_to_server(token_context, token_ttl=300):
    crypto = VirgilCrypto()

    # Account data from dashboard
    api_private_key = ""  # FILL THIS FIELD
    app_id = ""  # FILL THIS FIELD
    api_key_id = ""  # FILL THIS FIELD

    # Loading key for next usage
    imported_api_private_key = crypto.import_private_key(Utils.b64decode(api_private_key))

    # Instantiate token generator
    builder = JwtGenerator(
        app_id,
        imported_api_private_key,
        api_key_id,
        token_ttl,
        AccessTokenSigner()
    )

    identity = token_context.identity
    token = builder.generate_token(identity).to_string()
    print(token)  # print generated jwt token
    return token


############# CLIENT SIDE ####################


# Get generated token from server-side
def get_token_from_server(token_context):
    jwt_from_server = authenticated_query_to_server(token_context)
    return jwt_from_server


if __name__ == '__main__':

    # Prepare for Card Manager initialize
    crypto = VirgilCrypto()
    card_crypto = CardCrypto()
    validator = VirgilCardVerifier(card_crypto)
    token_provider = CallbackJwtProvider(get_token_from_server)

    # Basic card manager config
    card_manager = CardManager(
        card_crypto,
        access_token_provider=token_provider,
        card_verifier=validator
    )

    # generating key pair for creating card
    key_pair = crypto.generate_keys()

    # user identity for creating card
    username = ""  # FILL THIS FIELD

    # Preparing user public key for creating card
    public_key_data = crypto.export_public_key(key_pair.public_key)
    public_key_str = Utils.b64encode(public_key_data)

    # publishing card
    card = card_manager.publish_card(
        identity=username,
        private_key=key_pair.private_key,
        public_key=key_pair.public_key
    )
    print(vars(card))  # print registered Virgil Card


