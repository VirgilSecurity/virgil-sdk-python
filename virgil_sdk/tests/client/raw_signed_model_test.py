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
import json

from virgil_sdk.tests import BaseTest
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import RawSignedModel
from virgil_sdk.utils import Utils


class RawSignedModelSignerTest(BaseTest):

    def test_generate_pure_model_from_string(self):
        # STC-1
        rsm = RawSignedModel.from_string(self._compatibility_data["STC-1.as_string"])
        rsm_string = rsm.to_string()
        self.assertEqual(self._compatibility_data["STC-1.as_string"], rsm_string)
        self.assertEqual(
            Utils.json_loads(Utils.b64decode(self._compatibility_data["STC-1.as_string"]))["signatures"],
            rsm.signatures
        )

    def test_generate_pure_model_from_json(self):
        # STC-1
        rsm = RawSignedModel.from_json(self._compatibility_data["STC-1.as_json"])
        rsm_json = rsm.to_json()
        self.assertDictEqual(json.loads(self._compatibility_data["STC-1.as_json"]), json.loads(rsm_json))
        self.assertEqual(json.loads(self._compatibility_data["STC-1.as_json"])["signatures"], rsm.signatures)

    def test_generate_full_model_from_string(self):
        # STC-2
        rsm = RawSignedModel.from_string(self._compatibility_data["STC-2.as_string"])
        rsm_string = rsm.to_string()
        self.assertEqual(self._compatibility_data["STC-2.as_string"], rsm_string)
        self.assertEqual(
            json.dumps(
                json.loads(Utils.b64decode(self._compatibility_data["STC-2.as_string"]).decode())["signatures"],
                sort_keys=True
            ),
            json.dumps(list(map(lambda x: x.to_json(), rsm.signatures)), sort_keys=True)
        )

    def test_generate_full_model_from_json(self):
        # STC-2
        rsm = RawSignedModel.from_json(self._compatibility_data["STC-2.as_json"])
        rsm_json = rsm.to_json()
        self.assertDictEqual(json.loads(self._compatibility_data["STC-2.as_json"]), json.loads(rsm_json))
        self.assertEqual(
            json.dumps(json.loads(self._compatibility_data["STC-2.as_json"])["signatures"], sort_keys=True),
            json.dumps(list(map(lambda x: x.to_json(), rsm.signatures)), sort_keys=True)
        )

    def test_create_from_raw_card_content(self):
        # STC-1
        raw_signed_model = RawSignedModel.from_json(self._compatibility_data["STC-1.as_json"])
        raw_card_content = RawCardContent.from_signed_model(self._crypto, raw_signed_model)
        raw_signed_model_from_raw_card_content = RawSignedModel(raw_card_content.content_snapshot)
        self.assertEqual(raw_signed_model.content_snapshot, raw_signed_model_from_raw_card_content.content_snapshot)
        self.assertDictEqual(vars(raw_signed_model), vars(raw_signed_model_from_raw_card_content))
