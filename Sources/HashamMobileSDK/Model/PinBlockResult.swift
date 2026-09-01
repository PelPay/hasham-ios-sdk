import Foundation

/// An encrypted ISO-0 PIN block produced by `HashamMobile.createPinBlock`.
///
/// Forward `encryptedBlock` (or its `base64` / `hex` representation) to your backend,
/// which passes it to the Card API. The raw PIN never leaves the SDK.
public struct PinBlockResult: Sendable {
    /// Encrypted PIN block — 8 bytes for 3DES, 16 bytes for AES.
    public let encryptedBlock: Data

    public var base64: String { encryptedBlock.base64EncodedString() }
    public var hex: String { encryptedBlock.map { String(format: "%02x", $0) }.joined() }
}
