import Foundation

/// Result of `HashamMobile.sign(signedAt:)`.
/// Forward all three values to your backend for the IAM device-token exchange.
public struct SignResult: Sendable {
    /// Base64 RSA-SHA256 signature of `device:{deviceId}:op:{signedAt}`, produced by the
    /// device RSA-2048 Keychain private key. Passed to IAM as `device_signature`.
    public let deviceSignature: String
    /// Compact JWS (ES256) over `device:{deviceId}:op:{signedAt}`, signed by the SDK EC
    /// P-256 Keychain key. Passed to IAM as `sdk_signature` — proves genuine SDK binary presence.
    public let sdkSignature: String
    /// Unix timestamp (seconds) used in both signatures.
    public let signedAt: Int
}
