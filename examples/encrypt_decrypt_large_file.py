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

import io
from virgil_crypto import VirgilCrypto

CHUNK_SIZE = 1024


if __name__ == '__main__':

    # instantiate VirgilCrypto
    crypto = VirgilCrypto()

    # Generate new new key pair
    key_pair1 = crypto.generate_key_pair()

    crypto = VirgilCrypto()

    ############ Encrypt #################
    large_file = open("/PATH/TO/YOU/FILE", "rb")  # Use file like a byte stream
    encrypt_output_stream = io.BytesIO()  # Use sample byte stream

    crypto.encrypt_stream(
        large_file,
        encrypt_output_stream,
        key_pair1.public_key
    )

    large_file.close()

    encrypt_stream_data = encrypt_output_stream.getvalue()  # Get all bytes from stream


    ############ Decrypt ##################
    decrypt_input_stream = io.BytesIO(encrypt_stream_data)  # Create sample byte stream from encrypted in previous example bytes
    new_large_file = open("/PATH/TO/YOU/DECRYPTED/FILE", "wb")  # Create new file for decrypted data and use it as output stream

    crypto.decrypt_stream(
        decrypt_input_stream,
        new_large_file,
        key_pair1.private_key
    )

    new_large_file.close()
