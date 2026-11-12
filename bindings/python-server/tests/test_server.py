"""Python Server 绑定测试。"""

import asyncio
import hashlib
import pathlib
import tempfile

from did_sdk_server import ServerDidSdk


def test_server_assemble_sign_store_encrypted():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            sdk = ServerDidSdk(
                "did:web:issuer.example.com",
                mode="mock",
                key_vault_scheme="memory-keystore",
                key_vault_password="dev-password",
                vc_storage_path=tmp,
            )
            assert sdk.participant_did == "did:web:issuer.example.com"
            assert sdk.has_signer is True

            assembled = sdk.assemble_vc_with_proof(
                {"credentialSubject": {"id": "did:key:zSubject"}},
                "did:key:zSubject",
                {
                    "type": "Ed25519Signature2020",
                    "created": 1,
                    "verificationMethod": "did:web:issuer.example.com#key-1",
                    "jws": "zTest",
                },
            )
            assert assembled["issuer"] == "did:web:issuer.example.com"
            assert assembled["proof"]["jws"] == "zTest"

            signature = await sdk.sign_with_participant_key(b"payload", purpose="dev")
            assert len(signature) == 64

            vc = await sdk.issue_self_asserted_vc({"name": "Alice"})
            assert vc["proof"] is not None
            await sdk.store_vc(vc)
            loaded = await sdk.get_vc(vc["anchor_id"])
            assert loaded["id"] == vc["id"]

            anchor = vc["anchor_id"]
            digest = hashlib.blake2b(anchor.encode(), digest_size=32).hexdigest()
            file = pathlib.Path(tmp) / f"{digest}.json"
            raw = file.read_bytes()
            assert raw.startswith(b"DVCS")
            assert b"issuer" not in raw

    asyncio.run(run())
