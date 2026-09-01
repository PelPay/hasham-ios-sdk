import Foundation

/// Result of `HashamMobile.changePIN(from:pan:maskedPan:theme:)`.
/// Forward all three values to your backend PIN-change endpoint.
public struct ChangePinResult: Sendable {
    /// Hex ISO-0 PIN block for the current PIN, encrypted with the device working key.
    public let oldPinBlock: String
    /// Hex ISO-0 PIN block for the new PIN, encrypted with the device working key.
    public let newPinBlock: String
    /// Base64 RSA-OAEP-SHA256 encrypted PAN.
    /// Encrypted using the enc_public_key returned by IAM during attestation.
    /// The Card API decrypts this with the matching private key stored in Vault.
    public let wrappedPan: String
}
