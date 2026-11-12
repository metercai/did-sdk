import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import { DidSdk } from "../wrapper.js";

const VECTORS = JSON.parse(
  readFileSync(
    new URL("../../../tests/vectors/signing_vectors.json", import.meta.url),
    "utf8"
  )
);

const tempDirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "did-sdk-node-"));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("golden vectors", () => {
  test("did_signature_v1", () => {
    for (const vector of VECTORS.did_signature_v1) {
      const input = vector.input;
      const output = DidSdk.didSignatureV1Bytes(
        input.did,
        input.from,
        input.timestamp,
        input.anchor_ref,
        input.body_hash,
        input.rcpt_hash
      );
      expect(output.toString("utf8")).toBe(vector.expected_bytes_utf8);
    }
  });

  test("issued_vc_v1", () => {
    for (const vector of VECTORS.issued_vc_v1) {
      const input = vector.input;
      const output = DidSdk.issuedVcV1Bytes(
        input.issuer_did,
        input.subject_did,
        input.vc_type,
        input.vc_hash
      );
      expect(output.toString("utf8")).toBe(vector.expected_bytes_utf8);
    }
  });

  test("vp_v1", () => {
    for (const vector of VECTORS.vp_v1) {
      const input = vector.input;
      const output = DidSdk.vpV1Bytes(
        input.holder,
        input.challenge,
        input.domain,
        input.vc_hashes
      );
      expect(output.toString("utf8")).toBe(vector.expected_bytes_utf8);
    }
  });

  test("fixed seed signature", () => {
    for (const vector of VECTORS.fixed_seed_signature) {
      const output = DidSdk.ed25519SignWithSeed(
        vector.seed_hex,
        Buffer.from(vector.payload_utf8, "utf8")
      );
      expect(output.toString("hex")).toBe(vector.expected_signature_hex);
    }
  });
});

describe("SDK roundtrip", () => {
  test("async API and local VC/VP flow", async () => {
    const sdk = new DidSdk({
      mode: "mock",
      keyVaultScheme: "memory-keystore",
      keyVaultPassword: "test-password",
      vcStoragePath: tempDir(),
    });
    expect(sdk.resolvedConfig().mode).toBe("mock");

    const did = await sdk.generateDidKey();
    expect(did.startsWith("did:key:z")).toBe(true);
    expect(sdk.resolveDidKey(did).length).toBe(32);

    const signature = await sdk.signWithDidKey(Buffer.from("hello"), {
      purpose: "test",
    });
    expect(signature.length).toBe(64);

    const record = await sdk.createDid();
    expect(record.did.startsWith("did:key:z")).toBe(true);
    expect((await sdk.resolveDid(record.did))?.did).toBe(record.did);

    const vc = await sdk.issueSelfAssertedVc({
      name: "Alice",
      type: "TestCredential",
    });
    expect(vc.issuer).toBe(record.did);
    expect(vc.proof).toBeTruthy();
    await sdk.storeVc(vc);
    expect((await sdk.getVc(vc.anchor_id))?.id).toBe(vc.id);
    expect((await sdk.listVcs()).length).toBe(1);

    const vp = await sdk.buildVp([vc], "challenge-1", "example.com");
    expect(vp.holder).toBe(record.did);
    expect(vp.proof.proofValue).toBeTruthy();

    const header = await sdk.buildDidSignatureHeader(
      "alice@example.com",
      "anchor:abc",
      "body-hash",
      "rcpt-hash"
    );
    const verified = sdk.verifyDidSignatureHeader(
      header,
      "alice@example.com",
      "body-hash",
      "rcpt-hash"
    );
    expect(verified.valid).toBe(true);

    const authorization = await sdk.signIssueAuthorization(
      record.did,
      "TestCredential",
      "vc-hash",
      1700000000
    );
    expect(authorization.issuer_did).toBe(record.did);

    await sdk.removeVc(vc.anchor_id);
    expect(await sdk.getVc(vc.anchor_id)).toBeNull();
  });

  test("invalid VC maps to InvalidArgument", async () => {
    const sdk = new DidSdk({
      mode: "mock",
      keyVaultScheme: "memory-keystore",
      keyVaultPassword: "test-password",
      vcStoragePath: tempDir(),
    });
    await expect(sdk.storeVc({ id: "nope" })).rejects.toMatchObject({
      code: "InvalidArgument",
    });
  });
});
