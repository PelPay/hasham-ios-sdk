import Foundation

public enum HashamMobileError: LocalizedError {
    case notEnrolled
    case invalidPin(String)
    case invalidInput(String)
    case keyGenerationFailed(String)
    case keychainError(OSStatus)
    case decryptionFailed(String)
    case encryptionFailed(String)
    case enrollmentFailed(Int, String)   // HTTP status, error code
    case networkError(String)
    case invalidEnrollmentToken(String)

    public var errorDescription: String? {
        switch self {
        case .notEnrolled:                    return "Device is not enrolled — call enroll() first"
        case .invalidPin(let msg):            return "Invalid PIN: \(msg)"
        case .invalidInput(let msg):          return msg
        case .keyGenerationFailed(let msg):   return "Key generation failed: \(msg)"
        case .keychainError(let status):      return "Keychain error: \(status)"
        case .decryptionFailed(let msg):      return "Decryption failed: \(msg)"
        case .encryptionFailed(let msg):      return "Encryption failed: \(msg)"
        case .enrollmentFailed(let s, let c): return "Enrollment failed (HTTP \(s)): \(c)"
        case .networkError(let msg):          return "Network error: \(msg)"
        case .invalidEnrollmentToken(let msg): return "Invalid enrollment token: \(msg)"
        }
    }
}
