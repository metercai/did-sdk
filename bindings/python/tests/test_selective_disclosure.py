"""Python 选择性披露绑定测试。"""

import asyncio
import tempfile


from did_sdk import DidSdk


def test_selective_disclosure_roundtrip():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            client = DidSdk(
                mode="mock",
                key_vault_scheme="memory-keystore",
                key_vault_password="p",
                vc_storage_path=tmp + "/client",
            )
            await client.generate_did_key()
            issued = await client.issue_selective_vc(
                {
                    "type": "IDCardVC",
                    "idCardNumber": "123",
                    "name": "Alice",
                    "gender": "F",
                    "birthday": "1990-01-01",
                },
                ["name", "gender", "birthday"],
            )
            vc = issued["vc"]
            disclosures = issued["disclosures"]
            assert len(disclosures) == 3
            assert vc["credentialSubject"]["_sd_alg"] == "sha-256"
            assert "name" not in vc["credentialSubject"]

            await client.store_vc_with_disclosures(vc, disclosures)
            bundle = await client.get_vc_with_disclosures(vc["anchor_id"])
            assert len(bundle["disclosures"]) == 3
            assert await client.list_disclosable_attributes(vc["anchor_id"]) == [
                "birthday",
                "gender",
                "name",
            ]

            vp = await client.build_vp_selective(
                [{"credential": vc, "disclose": ["name"]}],
                "challenge",
                "example.com",
            )
            assert len(vp["disclosures"]) == 1
            assert vp["disclosures"][0][1] == "name"

    asyncio.run(run())
