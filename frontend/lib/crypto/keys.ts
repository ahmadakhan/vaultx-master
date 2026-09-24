import { bufToB64, b64ToBuf, genRandomBytes } from "./base";

const PBKDF2_ITERATIONS = 150000;
const AES_KEY_LEN = 256;

export async function deriveMasterKey(password: string, salt_b64?: string) {
  const enc = new TextEncoder();
  const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);

  let salt: Uint8Array<ArrayBuffer>;
  if (salt_b64) salt = new Uint8Array(b64ToBuf(salt_b64));
  else salt = new Uint8Array(genRandomBytes(16).buffer as ArrayBuffer);

  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    pwKey,
    { name: "AES-GCM", length: AES_KEY_LEN },
    false,
    ["encrypt", "decrypt"]
  );

  return { key, salt_b64: bufToB64(salt.buffer) };
}

export async function generateSearchKey() {
  const bytes = genRandomBytes(32);
  return bufToB64(bytes.buffer as ArrayBuffer);
}

export async function generateFileKey() {
  const bytes = genRandomBytes(32);
  return bufToB64(bytes.buffer as ArrayBuffer);
}

export async function generateRSAKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const pub = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const priv = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey_b64: bufToB64(pub),
    privateKey_b64: bufToB64(priv),
  };
}
