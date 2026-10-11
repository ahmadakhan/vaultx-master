import { aesDecryptArrayBuffer } from "./aes";
import { bufToB64 } from "./base";
import { deriveMasterKey, ACCOUNT_PBKDF2_ITERATIONS } from "./keys";

export interface UserKeyBundle {
  password_salt_b64: string;
  enc_master_key_b64: string;
  enc_master_key_iv: string;
  enc_search_key_b64: string;
  enc_search_key_iv: string;
  enc_private_key_b64: string;
  enc_private_key_iv: string;
  public_key_b64: string;
  key_bundle_version?: number;
  kdf_iterations?: number;
}

export function bundleAad(role: "master" | "search" | "private"): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`vaultx:key-bundle:v2:${role}`);
}

export async function unlockUserKeyBundle(password: string, bundle: UserKeyBundle) {
  const version = bundle.key_bundle_version ?? 1;
  if (version !== 1 && version !== 2) throw new Error("Unsupported key bundle version");
  if (version === 2 && (bundle.kdf_iterations ?? 0) < 600000) throw new Error("Invalid key bundle KDF");
  const { key } = await deriveMasterKey(password, bundle.password_salt_b64, bundle.kdf_iterations ?? ACCOUNT_PBKDF2_ITERATIONS);
  const unwrap = async (ct: string, iv: string, role: "master" | "search" | "private") => {
    const raw = await aesDecryptArrayBuffer(ct, iv, key, version === 2 ? bundleAad(role) : undefined);
    if (role !== "private" && raw.byteLength !== 32) throw new Error("Invalid vault key length");
    return bufToB64(raw);
  };
  return {
    masterKey_b64: await unwrap(bundle.enc_master_key_b64, bundle.enc_master_key_iv, "master"),
    searchKey_b64: await unwrap(bundle.enc_search_key_b64, bundle.enc_search_key_iv, "search"),
    privateKey_b64: await unwrap(bundle.enc_private_key_b64, bundle.enc_private_key_iv, "private"),
    publicKey_b64: bundle.public_key_b64,
  };
}
