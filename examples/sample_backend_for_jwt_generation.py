import json
import time

from virgil_crypto import VirgilCrypto
from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.utils import Utils
from flask import Flask, request, Response, jsonify

app = Flask(__name__)


def generate_jwt(identity):
    crypto = VirgilCrypto()

    # Account data from dashboard
    api_private_key = ""  # FILL THIS FIELD
    app_id = ""  # FILL THIS FIELD
    api_key_id = ""  # FILL THIS FIELD

    token_ttl = 10  # token time to live in seconds

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
    token = builder.generate_token(identity).to_string()  # generating token and transforming to string
    return token


@app.route('/authenticate', methods=['POST'])
def get_jwt():
    loaded_data = json.loads(request.data)  # loading data from request
    token = generate_jwt(loaded_data["identity"])  # generating jwt token
    return jsonify({"auth_token": token})  # return jwt string


if __name__ == '__main__':
    app.run()
