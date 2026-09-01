import Foundation
import Security
import DeviceCheck
import CryptoKit

/// Manages the per-device RSA-2048 key pair in the Keychain.
///
/// The private key is marked non-extractable (`kSecAttrIsExtractable: false`) — no code
/// can obtain the raw private key bytes. Its sole purpose is to unwrap the working key
/// returned by the SSM GI command.
///
/// Device ID on iOS is the App Attest key identifier, which is cryptographically bound
/// to the App Attest attestation certificate. On simulators (App Attest unsupported),
/// a stable UUID is generated instead.
internal final class DeviceKeyManager {

    private static let keychainService = "com.chamsswitch.hasham"
    private static let deviceIdAccount = "device_id"

    // MARK: - Device ID

    func getOrCreateDeviceId() async throws -> String {
        if let stored = keychainLoad(account: Self.deviceIdAccount) { return stored }

        let id: String
        if DCAppAttestService.shared.isSupported {
            id = try await DCAppAttestService.shared.generateKey()
        } else {
            // Simulator fallback — App Attest not available
            id = UUID().uuidString
        }
        keychainSave(account: Self.deviceIdAccount, value: id)
        return id
    }

    // MARK: - App Attest

    func generateAttestation(keyId: String, challenge: String) async throws -> Data {
        guard DCAppAttestService.shared.isSupported else {
            // Return empty data on simulator — IAM must have SKIP_PLATFORM_ATTESTATION=true
            return Data()
        }
        let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))
        return try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
    }

    // MARK: - RSA-2048 key pair for working key unwrapping

    func ensureRsaKeyPair(deviceId: String) throws -> SecKey {
        let tag = rsaKeyTag(deviceId)

        // Return existing public key if already generated
        if let privateKey = rsaPrivateKey(tag: tag),
           let publicKey = SecKeyCopyPublicKey(privateKey) {
            return publicKey
        }

        // Generate non-extractable RSA-2048 key pair
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:   true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrIsExtractable as String: false,       // private key bytes are never accessible
                kSecAttrAccessible as String:    kSecAttrAccessibleAfterFirstUnlock,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw HashamMobileError.keyGenerationFailed(
                error?.takeRetainedValue().localizedDescription ?? "Unknown"
            )
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw HashamMobileError.keyGenerationFailed("Cannot derive public key")
        }
        return publicKey
    }

    /// Returns (modulusHex, exponentHex) by parsing the PKCS#1 DER-encoded public key.
    func publicKeyComponents(deviceId: String) throws -> (modulus: String, exponent: String) {
        let tag = rsaKeyTag(deviceId)
        guard let privateKey = rsaPrivateKey(tag: tag),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw HashamMobileError.keyGenerationFailed("No RSA key for device \(deviceId)")
        }
        var cfError: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &cfError) as Data? else {
            throw HashamMobileError.keyGenerationFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "Cannot export public key"
            )
        }
        return try parsePkcs1Components(keyData)
    }

    /// Decrypt the wrapped working key (RSA-OAEP-SHA256) using the device private key.
    func unwrapWorkingKey(deviceId: String, wrappedKeyHex: String) throws -> Data {
        let tag = rsaKeyTag(deviceId)
        guard let privateKey = rsaPrivateKey(tag: tag) else {
            throw HashamMobileError.notEnrolled
        }
        let wrappedData = Data(hexString: wrappedKeyHex)
        var cfError: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA256,
            wrappedData as CFData,
            &cfError
        ) as Data? else {
            throw HashamMobileError.decryptionFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "Unknown"
            )
        }
        return plaintext
    }

    // MARK: - SDK identity EC P-256 key pair

    private static let sdkKeyTag = "com.chamsswitch.hasham.sdk.ec".data(using: .utf8)!

    /// Ensure the SDK identity key pair exists in the Keychain, creating it if absent.
    func ensureSdkKeyPair() throws {
        if sdkPrivateKey() != nil { return }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:    true,
                kSecAttrApplicationTag as String: Self.sdkKeyTag,
                kSecAttrIsExtractable as String:  false,
                kSecAttrAccessible as String:     kSecAttrAccessibleAfterFirstUnlock,
            ],
        ]
        var cfError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) != nil else {
            throw HashamMobileError.keyGenerationFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "EC keygen failed"
            )
        }
    }

    /// Returns the SDK identity public key as a PEM-encoded SPKI string.
    func sdkPublicKeyPem() throws -> String {
        try ensureSdkKeyPair()
        guard let privateKey = sdkPrivateKey(),
              let publicKey  = SecKeyCopyPublicKey(privateKey) else {
            throw HashamMobileError.keyGenerationFailed("Cannot retrieve SDK EC key")
        }
        var cfError: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &cfError) as Data? else {
            throw HashamMobileError.keyGenerationFailed(
                cfError?.takeRetainedValue().localizedDescription ?? "Cannot export SDK public key"
            )
        }
        return spkiDerToPem(ecPointToSpkiDer(point))
    }

    /// Signs `device_id:sdk_version:sdk_checksum` with the SDK EC private key and returns
    /// a compact JWS (ES256). IAM calls jose's compactVerify to validate it.
    func signSdkEnrollment(deviceId: String, sdkVersion: String, sdkChecksum: String) throws -> String {
        try ensureSdkKeyPair()
        guard let privateKey = sdkPrivateKey() else {
            throw HashamMobileError.keyGenerationFailed("No SDK EC key")
        }
        let payload = "\(deviceId):\(sdkVersion):\(sdkChecksum)".data(using: .utf8)!
        return try buildCompactJws(payload: payload) { signingInput in
            var cfError: Unmanaged<CFError>?
            guard let derSig = SecKeyCreateSignature(
                privateKey,
                .ecdsaSignatureMessageX962SHA256,
                signingInput as CFData,
                &cfError
            ) as Data? else {
                throw HashamMobileError.keyGenerationFailed(
                    cfError?.takeRetainedValue().localizedDescription ?? "EC sign failed"
                )
            }
            return try derToRawEcdsa(derSig)
        }
    }

    // MARK: - Private helpers

    private func sdkPrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:               kSecClassKey,
            kSecAttrApplicationTag as String:  Self.sdkKeyTag,
            kSecAttrKeyType as String:         kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:        kSecAttrKeyClassPrivate,
            kSecReturnRef as String:           true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private func rsaPrivateKey(tag: Data) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:               kSecClassKey,
            kSecAttrApplicationTag as String:  tag,
            kSecAttrKeyType as String:         kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String:        kSecAttrKeyClassPrivate,
            kSecReturnRef as String:           true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private func rsaKeyTag(_ deviceId: String) -> Data {
        "com.chamsswitch.hasham.rsa.\(deviceId)".data(using: .utf8)!
    }

    private func keychainLoad(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     Self.keychainService,
            kSecAttrAccount as String:     account,
            kSecReturnData as String:      true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func keychainSave(account: String, value: String) {
        let data = value.data(using: .utf8)!
        let attrs: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     Self.keychainService,
            kSecAttrAccount as String:     account,
            kSecValueData as String:       data,
            kSecAttrAccessible as String:  kSecAttrAccessibleAfterFirstUnlock,
        ]
        SecItemDelete(attrs as CFDictionary)
        SecItemAdd(attrs as CFDictionary, nil)
    }

    // MARK: - PKCS#1 DER parsing

    private func parsePkcs1Components(_ der: Data) throws -> (modulus: String, exponent: String) {
        var idx = der.startIndex
        guard der[idx] == 0x30 else { throw HashamMobileError.keyGenerationFailed("Not SEQUENCE") }
        idx = der.index(after: idx)
        idx = skipLength(der, from: idx)

        let (mod, idx2) = try readInteger(der, from: idx)
        let (exp, _)    = try readInteger(der, from: idx2)
        return (mod.hexString, exp.hexString)
    }

    private func skipLength(_ data: Data, from index: Data.Index) -> Data.Index {
        var i = index
        if data[i] & 0x80 == 0 { return data.index(after: i) }
        let count = Int(data[i] & 0x7F)
        return data.index(i, offsetBy: count + 1)
    }

    private func readLength(_ data: Data, from index: Data.Index) -> (Int, Data.Index) {
        var i = index
        if data[i] & 0x80 == 0 { return (Int(data[i]), data.index(after: i)) }
        let count = Int(data[i] & 0x7F); i = data.index(after: i)
        var len = 0
        for _ in 0..<count { len = len * 256 + Int(data[i]); i = data.index(after: i) }
        return (len, i)
    }

    private func readInteger(_ data: Data, from index: Data.Index) throws -> (Data, Data.Index) {
        var i = index
        guard data[i] == 0x02 else { throw HashamMobileError.keyGenerationFailed("Expected INTEGER") }
        i = data.index(after: i)
        let (len, nextI) = readLength(data, from: i); i = nextI
        var bytes = Data(data[i..<data.index(i, offsetBy: len)])
        if bytes.first == 0x00 { bytes = bytes.dropFirst() }  // strip sign byte
        return (Data(bytes), data.index(i, offsetBy: len))
    }
}

// MARK: - Data extensions

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init(hexString: String) {
        var data = Data()
        var hex = hexString
        while hex.count >= 2 {
            let byte = hex.prefix(2)
            hex = String(hex.dropFirst(2))
            if let b = UInt8(byte, radix: 16) { data.append(b) }
        }
        self = data
    }
}
