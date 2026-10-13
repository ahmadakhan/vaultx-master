/** Explicit contracts for native background transfer/key-store integrations.
 * Browser implementations must fail closed: no plaintext key export or
 * background completion is assumed when an adapter is unavailable.
 */
export interface SecureKeyStoreAdapter {
  readonly available: boolean;
  unwrapFileKey(reference: string): Promise<CryptoKey>;
}

export interface BackgroundTransferAdapter {
  readonly available: boolean;
  enqueue(request: { sessionId: string; fileName: string }): Promise<void>;
}

export const unavailablePlatformAdapter: SecureKeyStoreAdapter & BackgroundTransferAdapter = {
  available: false,
  async unwrapFileKey(): Promise<CryptoKey> { throw new Error("Secure platform key store is unavailable"); },
  async enqueue(): Promise<void> { throw new Error("Native background transfer adapter is unavailable"); },
};
