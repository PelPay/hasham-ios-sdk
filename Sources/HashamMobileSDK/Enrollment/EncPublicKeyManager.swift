import Foundation
import Security

/// Persists the tenant RSA public key (enc_public_key) returned by IAM during attestation.
/// Used to wrap the clear PAN for PIN-change operations — the Card API unwraps it with
/// the matching private key stored in Vault.
internal final class EncPublicKeyManager {

    private static let keychainService = "com.chamsswitch.hasham.encpub"

    // MARK: - Storage

    func store(deviceId: String, pemPublicKey: String) {
        guard let data = pemPublicKey.data(using: .utf8) else { return }
        let attrs: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    Self.keychainService,
            kSecAttrAccount as String:    deviceId,
            kSecValueData as String:      data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        SecItemDelete(attrs as CFDictionary)
        SecItemAdd(attrs as CFDictionary, nil)
    }

    func isAvailable(deviceId: String) -> Bool { load(deviceId: deviceId) != nil }

    // MARK: - PAN wrapping

    /// Encrypts `pan` with the stored RSA public key using RSA-OAEP-SHA256.
    /// Returns base64-encoded ciphertext.
    func wrapPan(deviceId: String, pan: String) throws -> String {
        guard let pem = load(deviceId: deviceId) else {
            throw HashamMobileError.encryptionFailed(
                "No enc_public_key stored for device \(deviceId) — tenant must configure an enc key"
            )
        }
        let publicKey = try parseRsaPublicKey(pem)
        guard let panData = pan.data(using: .utf8) else {
            throw HashamMobileError.encryptionFailed("PAN is not valid UTF-8")
        }
        var cfError: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA256,
            panData as CFData,
            &cfError
        ) as Data? else {
            throw HashamMobileError.encryptionFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "RSA-OAEP encrypt failed"
            )
        }
        return ciphertext.base64EncodedString()
    }

    // MARK: - Private

    private func load(deviceId: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: deviceId,
            kSecReturnData as String:  true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func parseRsaPublicKey(_ pem: String) throws -> SecKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----",     with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----",       with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----",   with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)
        guard let derData = Data(base64Encoded: stripped) else {
            throw HashamMobileError.encryptionFailed("Invalid PEM base64 for enc_public_key")
        }
        // SecKeyCreateWithData for RSA expects PKCS#1 format (not SPKI).
        // Strip the SubjectPublicKeyInfo wrapper if present (BEGIN PUBLIC KEY PEM).
        let keyData = stripSpkiIfPresent(derData)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:  kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &cfError) else {
            throw HashamMobileError.encryptionFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "Failed to import enc public key"
            )
        }
        return key
    }

    /// Strips the SubjectPublicKeyInfo (SPKI) ASN.1 wrapper from DER, returning the raw
    /// PKCS#1 RSAPublicKey bytes expected by `SecKeyCreateWithData`.
    private func stripSpkiIfPresent(_ der: Data) -> Data {
        var pos = 0
        let bytes = [UInt8](der)

        func readTag() -> UInt8? {
            guard pos < bytes.count else { return nil }
            defer { pos += 1 }
            return bytes[pos]
        }
        func readLength() -> Int? {
            guard pos < bytes.count else { return nil }
            let first = Int(bytes[pos]); pos += 1
            if first & 0x80 == 0 { return first }
            let extra = first & 0x7F
            guard pos + extra <= bytes.count else { return nil }
            var len = 0
            for _ in 0..<extra { len = len * 256 + Int(bytes[pos]); pos += 1 }
            return len
        }

        guard readTag() == 0x30 else { return der }   // outer SEQUENCE
        guard readLength() != nil else { return der }
        guard bytes[safe: pos] == 0x30 else { return der }  // algorithm identifier SEQUENCE
        guard readTag() == 0x30 else { return der }
        guard let algoLen = readLength() else { return der }
        pos += algoLen                                        // skip OID + NULL
        guard bytes[safe: pos] == 0x03 else { return der }  // BIT STRING
        guard readTag() == 0x03 else { return der }
        guard readLength() != nil else { return der }
        guard bytes[safe: pos] == 0x00 else { return der }  // no unused bits
        pos += 1
        guard pos < bytes.count else { return der }
        return Data(bytes[pos...])
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
