# Copyright (C) 2016-2019 Virgil Security Inc.
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

from virgil_crypto import VirgilCrypto, VirgilSeqCipher

CHUNK_SIZE = 1024


def read_in_chunks(file_obj, chunk_size=CHUNK_SIZE):  # Helper for chunked read file
    while True:
        data = file_obj.read(chunk_size)
        if not data:
            break
        yield data


if __name__ == '__main__':

    crypto = VirgilCrypto()
    large_file = open("/PATH/TO/YOU/FILE", "rb")

    chunk_list = []

    for chunk in read_in_chunks(large_file):
        chunk_list.append(bytearray(chunk))

    large_file.close()

    # Generate new new key pair
    key_pair1 = crypto.generate_keys()

    ############ Encrypt #################
    encrypt_seq_cipher = VirgilSeqCipher()  # Initialize Sequence Cipher
    encrypt_seq_cipher.addKeyRecipient(key_pair1.public_key.identifier, key_pair1.public_key.raw_key)  # Adding recipient for encryption

    encrypted_chunks = list()  # encrypted output
    encrypted_chunks.append(encrypt_seq_cipher.startEncryption())  # start encryption

    for index, chunk in enumerate(chunk_list):
        encrypted_chunks.append(encrypt_seq_cipher.process(chunk))  # encryption body
        if index == len(chunk_list) - 1:
            try:
                last_piece = encrypt_seq_cipher.finish()
                if last_piece:
                    encrypted_chunks.append(last_piece)
            except Exception as e:
                print(e)

    ############ Decrypt ##################
    decrypt_seq_cipher = VirgilSeqCipher()  # Initialize Sequence Cipher
    decrypt_seq_cipher.startDecryptionWithKey(key_pair1.private_key.identifier, key_pair1.private_key.raw_key)  # Start decryption with our recipient private key

    decrypted_chunks = list()
    for index, chunk in enumerate(encrypted_chunks):
        decrypted_chunks.append(decrypt_seq_cipher.process(chunk))  # decryption body
        if index == len(encrypted_chunks) - 1:
            print("Last index", index)
            try:
                last_piece = decrypt_seq_cipher.finish()
                if last_piece:
                    decrypted_chunks.append(last_piece)
            except Exception as e:
                print(e)

    new_large_file = open("/PATH/TO/YOU/DECRYPTED/FILE", "wb")  # Create new file for decrypted data

    for chunk in decrypted_chunks:  # write decrypted data into recently created file.
        new_large_file.write(bytearray(chunk))
    new_large_file.close()
