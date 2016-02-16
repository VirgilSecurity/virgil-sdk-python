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
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib

# Initialization of new Virgil client
token = '%TOKEN%'
ident_link = 'https://identity.virgilsecurity.com/v1'
virgil_card_link = 'https://keys.virgilsecurity.com/v3'
private_key_link = 'https://keyring.virgilsecurity.com/v3'
virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)

# Generate key pair
keys = cryptolib.CryptoWrapper.generate_keys(cryptolib.crypto_helper.VirgilKeyPair.Type_EC_SECP521R1, '%Password%')

# Create new Virgil card
type = 'email'
value = 'example@mail.com'
verifyResponse = virgil_hub.identity.verify(type, value)
identResponse = virgil_hub.identity.confirm('%Confiration code%', verifyResponse['action_id'])
data ={'Field1': 'Data1', 'Field2': 'Data2'}
new_card = virgil_hub.virgilcard.create_card(type, value, data, identResponse['validation_token'],
                                        keys['private_key'], '%Password%', keys['public_key'])

# Obtain public key - unsigned request
pk = virgil_hub.virgilcard.get_public_key('%public key id%')

# Obtain public key - signed request
pks = virgil_hub.virgilcard.get_public_key('%Public key id%', True, '%signer card id%', '%Private key%', '%Password$')

# Search application
value = '%Application name%'
my_app = virgil_hub.virgilcard.search_app(value)

# Search virgil card
value = '%email address%'
search_result = virgil_hub.virgilcard.search_card(value)

# Obtain card by ID
cardID = '%Card ID%'
my_card = virgil_hub.virgilcard.get_virgil_card(cardID)

# Sign virgil card
virgil_hub.virgilcard.sign_card("%Signed card id%", "%signer card id%", "%private key%", "%Password%")

# Unsign virgil card
virgil_hub.virgilcard.unsign_card("%Signed card id%", "%signer card id%", "%private key%", "%Password%")

# Load private key to private key service
recipient_card = virgil_hub.virgilcard.search_app('com.virgilsecurity.private-keys')
recipient_id = recipient_card[0]['id']
recipient_pub_key = recipient_card[0]['public_key']['public_key']
virgil_hub.privatekey.load_private_key(recipient_pub_key, recipient_id, "%Private key%", "%Signer card ID%", "%Pswd%")

# Get private key
type = 'email'
value = '%email address%'
verifyResponse = virgil_hub.identity.verify(type, value)
identResponse = virgil_hub.identity.confirm("%Confirmation code%", verifyResponse['action_id'])
recipient_card = virgil_hub.virgilcard.search_app('com.virgilsecurity.private-keys')
recipient_id = recipient_card[0]['id']
recipient_pub_key = recipient_card[0]['public_key']['public_key']
private_key_from_service = virgil_hub.privatekey.grab_private_key(
    recipient_pub_key, recipient_id, type, value, identResponse['validation_token'], '%Pswd%', "%Signer card ID%")

# Delete private key
recipient_card = virgil_hub.virgilcard.search_app('com.virgilsecurity.private-keys')
recipient_id = recipient_card[0]['id']
recipient_pub_key = recipient_card[0]['public_key']['public_key']
virgil_hub.privatekey.delete_private_key(recipient_pub_key, recipient_id, "%Private key%", "%Signer card ID%", "%Pswd%")

# Delete Virgil card
type = 'email'
value = '%email address%'
verifyResponse = virgil_hub.identity.verify(type, value)
identResponse = virgil_hub.identity.confirm(input('Enter confirmation code:'), verifyResponse['action_id'])
virgil_hub.virgilcard.delete_card(type, value, identResponse['validation_token'], '%Card id%', '%Private key%', '%Pswd%')

# Delete public key
type = 'email'
value = '%email address'
verifyResponse = virgil_hub.identity.verify(type, value)
identResponse = virgil_hub.identity.confirm(input('Enter confirmation code:'), verifyResponse['action_id'])
identities = []
val = {"type": type, "value": value,
    "validation_token": helper.Helper.remove_slashes(identResponse['validation_token'])}
identities.append(val)
virgil_hub.virgilcard.delete_public_key('%Key id%', identities, '%Card id%', '%Private key%', '%Password%')

# Test cryptolib
# Generate key pair
keys = cryptolib.CryptoWrapper.generate_keys(cryptolib.crypto_helper.VirgilKeyPair.Type_EC_SECP224R1, "%Password%")
print(keys['public_key'], keys['private_key'])

# Sign data with private key
sign = cryptolib.CryptoWrapper.sign('%To be signed%', '%Private key%', '%Password')

# Verify signature under data
verify = cryptolib.CryptoWrapper.verify('%To be signed%', sign, '%Public key')

# Encrypt data with recipient's public key
enc = cryptolib.CryptoWrapper.encrypt('%To be encrypted%', '%Recipient id%', '%Recipient public key%')

# Decrypt data with recipient's private key
data = cryptolib.CryptoWrapper.decrypt('%To be decrypted%', '%Recipient id%', '%Recipient private key%', '%Password%')
