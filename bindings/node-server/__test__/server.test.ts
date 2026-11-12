import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import { ServerDidSdk } from "../wrapper.js";

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "did-sdk-server-"));
  dirs.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("ServerDidSdk", () => {
  test("assemble, local signer and encrypted VC store", async () => {
    const sdk = new ServerDidSdk("did:web:issuer.example.com", {
      mode: "mock",
      keyVaultScheme: "memory-keystore",
      keyVaultPassword: "dev-password",
      vcStoragePath: tempDir(),
    });
    expect(sdk.participantDid).toBe("did:web:issuer.example.com");
    expect(sdk.hasSigner).toBe(true);

    const proof = {
      type: "Ed25519Signature2020",
      created: 1,
      verificationMethod: "did:web:issuer.example.com#key-1",
      jws: "zTest",
    };
    const assembled = sdk.assembleVcWithProof(
      { credentialSubject: { id: "did:key:zSubject" } },
      "did:key:zSubject",
      proof
    );
    expect(assembled.issuer).toBe("did:web:issuer.example.com");
    expect(assembled.proof.jws).toBe("zTest");

    const signature = await sdk.signWithParticipantKey(Buffer.from("payload"), {
      purpose: "dev",
    });
    expect(signature.length).toBe(64);

    const issued = await sdk.issueSelfAssertedVc({ name: "Alice" });
    expect(issued.proof).toBeTruthy();
    await sdk.storeVc(issued);
    const loaded = await sdk.getVc(issued.anchor_id);
    expect(loaded?.id).toBe(issued.id);
  });
});
