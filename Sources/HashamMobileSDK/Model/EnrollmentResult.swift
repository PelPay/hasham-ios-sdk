import Foundation

/// Returned after successful device enrollment.
public struct EnrollmentResult: Sendable {
    /// The device ID — pass this to your backend as the `X-Device-ID` header.
    public let deviceId: String
}
