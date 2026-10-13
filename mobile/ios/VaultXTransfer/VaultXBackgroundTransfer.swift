// Native iOS source only. This file is never bundled into the browser
// frontend and provides no browser support or browser key-storage fallback.
import Foundation
import Security

/// Native iOS adapter: OS-managed background URLSession plus device-only
/// Keychain storage for wrapped transfer keys and session metadata.
public final class VaultXBackgroundTransfer: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    private let service = "com.vaultx.transfer.keys"
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.background(withIdentifier: "com.vaultx.transfer.background")
        configuration.sessionSendsLaunchEvents = true
        configuration.waitsForConnectivity = true
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    public func storeWrappedKey(_ data: Data, account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account,
                                    kSecValueData as String: data,
                                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        SecItemDelete(query as CFDictionary)
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw NSError(domain: "VaultX", code: 1) }
    }

    public func loadWrappedKey(account: String) throws -> Data {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { throw NSError(domain: "VaultX", code: 2) }
        return data
    }

    public func upload(request: URLRequest, fileURL: URL) -> URLSessionUploadTask {
        session.uploadTask(with: request, fromFile: fileURL)
    }
}
