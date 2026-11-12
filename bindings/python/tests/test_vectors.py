"""Python 绑定测试：golden vector、异步 roundtrip、异常与配置。"""

import asyncio
import json
import pathlib
import tempfile

import pytest

from did_sdk import DidSdk, InvalidArgumentError, UserRejectedError

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[3] / "tests/vectors/signing_vectors.json").read_text()
)


def test_did_signature_v1_bytes():
    for case in VECTORS["did_signature_v1"]:
        data = case["input"]
        out = DidSdk.did_signature_v1_bytes(
            did=data["did"],
            from_=data["from"],
            timestamp=data["timestamp"],
            anchor_ref=data["anchor_ref"],
            body_hash=data["body_hash"],
            rcpt_hash=data["rcpt_hash"],
        )
        assert out.decode() == case["expected_bytes_utf8"]


def test_issued_vc_v1_bytes():
    for case in VECTORS["issued_vc_v1"]:
        data = case["input"]
        out = DidSdk.issued_vc_v1_bytes(
            issuer_did=data["issuer_did"],
            subject_did=data["subject_did"],
            vc_type=data["vc_type"],
            vc_hash=data["vc_hash"],
        )
        assert out.decode() == case["expected_bytes_utf8"]


def test_vp_v1_bytes():
    for case in VECTORS["vp_v1"]:
        data = case["input"]
        out = DidSdk.vp_v1_bytes(
            holder=data["holder"],
            challenge=data["challenge"],
            domain=data["domain"],
            vc_hashes=data["vc_hashes"],
        )
        assert out.decode() == case["expected_bytes_utf8"]


def test_fixed_seed_signature():
    for case in VECTORS["fixed_seed_signature"]:
        out = DidSdk.ed25519_sign_with_seed(
            case["seed_hex"], case["payload_utf8"].encode()
        )
        assert out.hex() == case["expected_signature_hex"]


def test_unknown_override_is_rejected():
    with pytest.raises(ValueError):
        DidSdk(not_a_real_option="x")


def test_async_roundtrip():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            sdk = DidSdk(
                mode="mock",
                key_vault_scheme="memory-keystore",
                key_vault_password="test-password",
                vc_storage_path=tmp,
            )
            assert sdk.resolved_config()["mode"] == "mock"

            did = await sdk.generate_did_key()
            assert did.startswith("did:key:z")
            public_key = sdk.resolve_did_key(did)
            assert len(public_key) == 32

            signature = await sdk.sign_with_did_key(b"hello", purpose="test")
            assert len(signature) == 64

            record = await sdk.create_did()
            assert record["did"].startswith("did:key:z")
            assert (await sdk.resolve_did(record["did"]))["did"] == record["did"]

            vc = await sdk.issue_self_asserted_vc(
                {"name": "Alice", "type": "TestCredential"}
            )
            assert vc["issuer"] == record["did"]
            assert vc["proof"] is not None
            anchor_id = vc["anchor_id"]
            await sdk.store_vc(vc)
            loaded = await sdk.get_vc(anchor_id)
            assert loaded["id"] == vc["id"]
            assert len(await sdk.list_vcs()) == 1

            vp = await sdk.build_vp([vc], "challenge-1", "example.com")
            assert vp["holder"] == record["did"]
            assert vp["proof"]["proofValue"]

            header = await sdk.build_did_signature_header(
                "alice@example.com", "anchor:abc", "body-hash", "rcpt-hash"
            )
            result = sdk.verify_did_signature_header(
                header, "alice@example.com", "body-hash", "rcpt-hash"
            )
            assert result["valid"] is True

            auth = await sdk.sign_issue_authorization(
                record["did"], "TestCredential", "vc-hash", 1700000000
            )
            assert auth["issuer_did"] == record["did"]

            await sdk.remove_vc(anchor_id)
            assert await sdk.get_vc(anchor_id) is None

    asyncio.run(run())


def test_user_rejected_error_is_importable():
    assert issubclass(UserRejectedError, RuntimeError)
    assert issubclass(InvalidArgumentError, ValueError)
