/**
 * User key setup and management for VaultX authentication.
 */

import { bufToB64, b64ToBuf, genRandomBytes } from "./base";
import { memorySession } from './context';
import { aesEncryptArrayBuffer } from './aes';
import { bundleAad } from './bundle';

export const ACCOUNT_PBKDF2_ITERATIONS = 150000;
export const CURRENT_ACCOUNT_PBKDF2_ITERATIONS = 600000;
const AES_KEY_LEN = 256;

export interface UserKeys {
  password_salt_b64: string;
  enc_master_key_b64: string;
  enc_master_key_iv: string;
  enc_search_key_b64: string;
  enc_search_key_iv: string;
  enc_private_key_b64: string;
  enc_private_key_iv: string;
  public_key_b64: string;
  kdf_iterations: number;
  key_bundle_version: number;
}

export interface UserKeysResponse {
  password_salt_b64: string;
  enc_master_key_b64: string;
  enc_master_key_iv: string;
  enc_search_key_b64: string;
  enc_search_key_iv: string;
  enc_private_key_b64: string;
  enc_private_key_iv: string;
  public_key_b64: string;
  kdf_iterations: number;
  key_bundle_version: number;
}

export async function deriveMasterKey(password: string, salt_b64?: string, iterations = ACCOUNT_PBKDF2_ITERATIONS): Promise<{ key: CryptoKey; salt_b64: string }> {
  if (!Number.isSafeInteger(iterations) || iterations < ACCOUNT_PBKDF2_ITERATIONS || iterations > 10000000) {
    throw new Error("Unsupported password KDF parameters");
  }

  const enc = new TextEncoder();
  const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);

  let salt: Uint8Array<ArrayBuffer>;
  if (salt_b64) {
    salt = new Uint8Array(b64ToBuf(salt_b64));
  } else {
    salt = new Uint8Array(genRandomBytes(16).buffer as ArrayBuffer);
  }
  if (salt.byteLength !== 16) throw new Error("Invalid password salt");

  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    pwKey,
    { name: "AES-GCM", length: AES_KEY_LEN },
    false,
     ["encrypt", "decrypt"]
  );

  return { key, salt_b64: bufToB64(salt.buffer) };
}

export async function deriveSearchKey(masterKey: CryptoKey, tenantId: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const salt = encoder.encode(`search_${tenantId}_salt`);
  
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 300000,
      hash: "SHA-256"
    },
    masterKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function generateRSAKeyPair(): Promise<{ publicKey_b64: string; privateKey_b64: string }> {
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

export async function encryptWithMasterKey(
  data: ArrayBuffer,
  masterKey: CryptoKey,
  iv?: Uint8Array,
  tenantId?: string
): Promise<{ ciphertext_b64: string; iv_b64: string }> {
  const encoder = new TextEncoder();
  let additionalData: ArrayBuffer | undefined;
  
  if (tenantId) {
    additionalData = encoder.encode(`tenant:${tenantId}_protected_data`).buffer as ArrayBuffer;
  }
  
  const fileIv = iv || new Uint8Array(crypto.getRandomValues(new Uint8Array(12)));
  
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
       iv: fileIv as BufferSource,
       additionalData: additionalData as BufferSource | undefined,
      tagLength: 128,
    },
    masterKey,
    data
  );
  
  return {
    ciphertext_b64: bufToB64(encrypted),
    iv_b64: bufToB64(fileIv.slice().buffer as ArrayBuffer)
  };
}

export async function decryptWithMasterKey(
  ciphertext_b64: string,
  iv_b64: string,
  masterKey: CryptoKey,
  tenantId?: string
): Promise<ArrayBuffer> {
  const encrypted = b64ToBuf(ciphertext_b64);
  const iv = new Uint8Array(b64ToBuf(iv_b64));
  
  const encoder = new TextEncoder();
  let additionalData: ArrayBuffer | undefined;
  
  if (tenantId) {
    additionalData = encoder.encode(`tenant:${tenantId}_protected_data`).buffer as ArrayBuffer;
  }
  
  return await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
       iv: iv as BufferSource,
       additionalData: additionalData as BufferSource | undefined,
      tagLength: 128,
    },
    masterKey,
    encrypted
  );
}

export async function setupUserKeys(password: string): Promise<UserKeys> {
  if (!password) throw new Error("A vault password is required to create a key bundle")
  
  // Registration creates a fresh salt. Login derives from the salt carried by
  // the server-returned envelope in ``unlockUserKeyBundle``.
  const masterKeyResponse = await deriveMasterKey(password, undefined, CURRENT_ACCOUNT_PBKDF2_ITERATIONS);
  
  const masterKey = masterKeyResponse.key;
  const masterPlain = crypto.getRandomValues(new Uint8Array(32));
  const searchPlain = crypto.getRandomValues(new Uint8Array(32));
  const rsaKeys = await generateRSAKeyPair();
  const privatePlain = b64ToBuf(rsaKeys.privateKey_b64);
  const masterEncrypted = await aesEncryptArrayBuffer(masterPlain.buffer, masterKey, undefined, bundleAad("master"));
  const searchEncrypted = await aesEncryptArrayBuffer(searchPlain.buffer, masterKey, undefined, bundleAad("search"));
  const privateEncrypted = await aesEncryptArrayBuffer(privatePlain, masterKey, undefined, bundleAad("private"));
  
  return {
    password_salt_b64: masterKeyResponse.salt_b64,
    enc_master_key_b64: masterEncrypted.ciphertext_b64,
    enc_master_key_iv: masterEncrypted.iv_b64,
    enc_search_key_b64: searchEncrypted.ciphertext_b64,
    enc_search_key_iv: searchEncrypted.iv_b64,
    enc_private_key_b64: privateEncrypted.ciphertext_b64,
    enc_private_key_iv: privateEncrypted.iv_b64,
    public_key_b64: rsaKeys.publicKey_b64,
    kdf_iterations: CURRENT_ACCOUNT_PBKDF2_ITERATIONS,
    key_bundle_version: 2
  };
}

export async function prepareUserKeyBundle(password: string): Promise<UserKeysResponse> {
  const keys = await setupUserKeys(password);
  return {
    ...keys,
    kdf_iterations: keys.kdf_iterations,
    key_bundle_version: keys.key_bundle_version
  };
}

export async function deriveUserKeysFromBundle(
  keys: UserKeys,
  password: string
): Promise<CryptoKey> {
  const derived = await deriveMasterKey(password, keys.password_salt_b64, keys.kdf_iterations);
  return derived.key;
}

export async function getUserKeysFromStorage(userId: string): Promise<UserKeys> {
  const storedKeys = memorySession.getItem(`vaultx_keys_${userId}`);
  if (!storedKeys) {
    throw new Error("User keys not found in storage");
  }
  
  return JSON.parse(storedKeys) as UserKeys;
}

export async function storeUserKeys(userId: string, keys: UserKeys): Promise<void> {
  memorySession.setItem(`vaultx_keys_${userId}`, JSON.stringify(keys));
}

export function clearUserKeys(userId: string): void {
  memorySession.removeItem(`vaultx_keys_${userId}`);
  memorySession.removeItem(`vaultx_password_${userId}`);
  memorySession.removeItem(`vaultx_password_salt_${userId}`);
}

export async function createUserSession(userId: string, password?: string): Promise<UserKeys> {
  void userId // retained for callers during the migration; identity never derives a password
  if (!password) throw new Error("A vault password is required to create a key bundle")
  return await setupUserKeys(password);
}
