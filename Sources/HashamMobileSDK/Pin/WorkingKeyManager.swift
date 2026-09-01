import Foundation
import Security

/// Stores the working key at rest by re-encrypting it under the device's non-extractable
/// RSA-2048 private key (RSA-OAEP-SHA256). The Keychain entry holds only ciphertext;
/// the plaintext is materialised for the duration of `withKey` then zeroed.
internal final class WorkingKeyManager {

    private static let keychainService = "com.chamsswitch.hasham"

    // MARK: - Public API

    func store(deviceId: String, workingKey: Data) throws {
        let publicKey = try fetchPublicKey(deviceId: deviceId)
        var cfError: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA256,
            workingKey as CFData,
            &cfError
        ) as Data? else {
            throw HashamMobileError.encryptionFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "Unknown"
            )
        }
        try keychainSave(account: account(deviceId), data: ciphertext)
    }

    /// Decrypt the stored working key, pass it to `block`, then zero the plaintext immediately.
    /// The block is non-escaping — the plaintext never outlives this call.
    func withKey<T>(deviceId: String, block: (Data) throws -> T) throws -> T {
        let privateKey = try fetchPrivateKey(deviceId: deviceId)
        guard let ciphertext = keychainLoad(account: account(deviceId)) else {
            throw HashamMobileError.notEnrolled
        }
        var cfError: Unmanaged<CFError>?
        guard var plaintext = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA256,
            ciphertext as CFData,
            &cfError
        ) as Data? else {
            throw HashamMobileError.decryptionFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "Unknown"
            )
        }
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        return try block(plaintext)
    }

    func hasKey(deviceId: String) -> Bool {
        return keychainLoad(account: account(deviceId)) != nil
    }

    func clear(deviceId: String) {
        keychainDelete(account: account(deviceId))
    }

    // MARK: - Private

    private func account(_ deviceId: String) -> String { "working_key.\(deviceId)" }

    private func fetchPrivateKey(deviceId: String) throws -> SecKey {
        let tag = "com.chamsswitch.hasham.rsa.\(deviceId)".data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String:        kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String:       kSecAttrKeyClassPrivate,
            kSecReturnRef as String:          true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
            throw HashamMobileError.notEnrolled
        }
        return (item as! SecKey)
    }

    private func fetchPublicKey(deviceId: String) throws -> SecKey {
        guard let pub = SecKeyCopyPublicKey(try fetchPrivateKey(deviceId: deviceId)) else {
            throw HashamMobileError.keyGenerationFailed("Cannot derive public key")
        }
        return pub
    }

    private func keychainSave(account: String, data: Data) throws {
        let attrs: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    Self.keychainService,
            kSecAttrAccount as String:    account,
            kSecValueData as String:      data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        SecItemDelete(attrs as CFDictionary)
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw HashamMobileError.keychainError(status) }
    }

    private func keychainLoad(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String:  true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    private func keychainDelete(account: String) {
        let attrs: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(attrs as CFDictionary)
    }
}
