import { deriveMasterKey, generateSearchKey, generateRSAKeyPair, generateFileKey } from "./keys";
import { aesEncryptArrayBuffer } from "./aes";

export async function prepareUserKeyBundle(password: string) {
  // 1. Derive password-based key
  const { key: pwKey, salt_b64 } = await deriveMasterKey(password);

  // 2. Generate core keys
  const masterKey_b64 = await generateFileKey(); // Km
  const searchKey_b64 = await generateSearchKey(); // Ks
  const rsaPair = await generateRSAKeyPair(); // public/private

  // 3. Encrypt sensitive ones under password-derived key
  const encMaster = await aesEncryptArrayBuffer(
    Uint8Array.from(atob(masterKey_b64), (c) => c.charCodeAt(0)).buffer,
    pwKey
  );

  const encSearch = await aesEncryptArrayBuffer(
    Uint8Array.from(atob(searchKey_b64), (c) => c.charCodeAt(0)).buffer,
    pwKey
  );

  const privBuf = Uint8Array.from(atob(rsaPair.privateKey_b64), (c) => c.charCodeAt(0)).buffer;
  const encPriv = await aesEncryptArrayBuffer(privBuf, pwKey);

  // 4. Return the payload to send to backend
  return {
    password_salt_b64: salt_b64,
    enc_master_key_b64: encMaster.ciphertext_b64,
    enc_master_key_iv: encMaster.iv_b64,
    enc_search_key_b64: encSearch.ciphertext_b64,
    enc_search_key_iv: encSearch.iv_b64,
    enc_private_key_b64: encPriv.ciphertext_b64,
    enc_private_key_iv: encPriv.iv_b64,
    public_key_b64: rsaPair.publicKey_b64,
  };
}
