"""
Security Test Suite for VaultX Enterprise Fixes

Comprehensive tests for the security fixes implemented in VaultX
to ensure enterprise-grade security standards are met.
"""

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import { createChunkEncryptionContext } from '../lib/crypto/chunking';
import { ZeroTrustCryptoStreamer } from '../lib/crypto/zero-trust-crypto-streamer';
import { MemoryWiper } from '../lib/crypto/memory-wiper';
import { setVaultXContext, clearVaultXContext, getVaultXContext } from '../lib/crypto/context';
import { deriveMasterKey, setupUserKeys } from '../lib/crypto/setupUserKeys';

// Mock crypto module for testing
const mockCrypto = {
  subtle: {
    importKey: jest.fn(),
    deriveKey: jest.fn(),
    exportKey: jest.fn(),
    encrypt: jest.fn(),
    decrypt: jest.fn(),
    generateKey: jest.fn(),
    wrapKey: jest.fn(),
    unwrapKey: jest.fn()
  },
  getRandomValues: jest.fn()
};

Object.defineProperty(global, 'crypto', { value: mockCrypto });

describe('VaultX Enterprise Security Tests', () => {
  let memoryWiper: MemoryWiper;
  
  beforeEach(() => {
    memoryWiper = new MemoryWiper({ enabled: true, wipeOnErrors: true });
  });
  
  afterEach(() => {
    memoryWiper.cleanup();
    clearVaultXContext();
  });
  
  describe('ZeroTrustCryptoStreamer Security Tests', () => {
    test('should derive master key with PBKDF2', async () => {
      const cryptoStreamer = new ZeroTrustCryptoStreamer({
        chunkSize: 1024,
        enablePostQuantum: false,
        memoryWipeEnabled: true
      });
      
      const password = 'testPassword123';
      const tenantId = 'test-tenant-1';
      
      // Mock crypto operations
      mockCrypto.subtle.importKey.mockResolvedValue({} as CryptoKey);
      mockCrypto.subtle.deriveKey.mockResolvedValue({} as CryptoKey);
      
      await expect(cryptoStreamer.deriveMasterKey(password, tenantId)).resolves.toBeDefined();
      expect(mockCrypto.subtle.importKey).toHaveBeenCalled();
      expect(mockCrypto.subtle.deriveKey).toHaveBeenCalled();
    });
    
    test('should generate base IV securely', () => {
      const cryptoStreamer = new ZeroTrustCryptoStreamer();
      
      const iv = cryptoStreamer.generateBaseIV();
      
      expect(iv).toHaveLength(12);
      expect(typeof iv).toBe('object');
      expect(iv.byteLength).toBe(12);
    });
    
    test('should increment IV correctly', () => {
      const cryptoStreamer = new ZeroTrustCryptoStreamer();
      
      const baseIV = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);
      const chunkIndex = 1;
      
      const incremented = cryptoStreamer.incrementIV(baseIV, chunkIndex);
      
      expect(incremented.byteLength).toBe(12);
      expect(incremented[0x08]).toBe(chunkIndex); // Byte at position 8 should contain chunk index
    });
    
    test('should validate chunk index range', () => {
      const cryptoStreamer = new ZeroTrustCryptoStreamer();
      
      expect(() => cryptoStreamer.incrementIV(new Uint8Array(12), -1)).toThrow();
      expect(() => cryptoStreamer.incrementIV(new Uint8Array(12), 0)).not.toThrow();
      expect(() => cryptoStreamer.incrementIV(new Uint8Array(12), 0xffffffff)).toThrow(); // Too large
    });
  });
  
  describe('MemoryWiper Security Tests', () => {
    test('should wipe sensitive data', async () => {
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      
      memoryWiper.wipe(testData);
      
      // Data should be zeroed
      for (let i = 0; i < testData.length; i++) {
        expect(testData[i]).toBe(0);
      }
    });
    
    test('should perform secure wipe', async () => {
      await expect(memoryWiper.performSecureWipe()).resolves.toBeUndefined();
    });
    
    test('should cleanup memory monitoring', () => {
      expect(() => memoryWiper.cleanup()).not.toThrow();
    });
  });
  
  describe('VaultX Context Security Tests', () => {
    test('should set and get vault context', () => {
      const testContext = {
        accessToken: 'test-token-123',
        masterKey_b64: 'test-master-key',
        searchKey_b64: 'test-search-key',
        privateKey_b64: 'test-private-key',
        publicKey_b64: 'test-public-key',
        tenantId: 'test-tenant',
        expiresAt: Date.now() + 3600000
      };
      
      setVaultXContext(testContext);
      const retrievedContext = getVaultXContext();
      
      expect(retrievedContext).toEqual(testContext);
    });
    
    test('should clear vault context', () => {
      const testContext = {
        accessToken: 'test-token',
        masterKey_b64: 'test-master-key',
        searchKey_b64: 'test-search-key',
        privateKey_b64: 'test-private-key',
        publicKey_b64: 'test-public-key',
      };
      
      setVaultXContext(testContext);
      clearVaultXContext();
      
      expect(() => getVaultXContext()).toThrow();
    });
  });
  
  describe('User Key Management Tests', () => {
    test('should setup user keys', async () => {
      const userId = 'test-user-123';
      
      // Mock memory session
      const originalMemorySession = memorySession;
      memorySession = {
        getItem: jest.fn().mockReturnValue('testPassword'),
        setItem: jest.fn(),
        removeItem: jest.fn()
      };
      
      await expect(setupUserKeys(userId)).resolves.toBeDefined();
      
      memorySession = originalMemorySession;
    });
  });
});

// Mock memory session for testing
const memorySession = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn()
};

// Export for Vitest
export { mockCrypto, memorySession };