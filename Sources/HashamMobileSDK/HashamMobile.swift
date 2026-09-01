import Foundation
import Security
import UIKit

/// The main entry point for the Hasham Mobile SDK.
///
/// **Typical lifecycle**
/// ```swift
/// // Production — uses the default discovery URL (api.chamsswitch.com)
/// let hasham = HashamMobile()
///
/// // Staging / dev — override the well-known endpoint
/// let hasham = HashamMobile(config: HashamMobileConfig(
///     discoveryUrl: "https://api.dev.chamsswitch.com/auth/.well-known/mobile-sdk"
/// ))
///
/// // After the user authenticates with your backend and receives an enrollment token:
/// let result = try await hasham.enroll(enrollmentToken: token)
/// // Store result.deviceId — pass it as X-Device-ID on every subsequent card operation.
///
/// // On every PIN operation:
/// var pin = Array("1234")   // CharArray — SDK zeros it on return
/// let block = try hasham.createPinBlock(pan: card.pan, pin: &pin)
/// // Forward block.hex (or block.base64) to your backend → Card API
/// ```
public final class HashamMobile {

    private let deviceKeyManager:    DeviceKeyManager
    private let workingKeyManager:   WorkingKeyManager
    private let encPublicKeyManager: EncPublicKeyManager
    private let pinBlockBuilder:     PinBlockBuilder
    private let enrollmentClient:    EnrollmentClient

    public init(config: HashamMobileConfig = HashamMobileConfig()) {
        deviceKeyManager    = DeviceKeyManager()
        workingKeyManager   = WorkingKeyManager()
        encPublicKeyManager = EncPublicKeyManager()
        pinBlockBuilder     = PinBlockBuilder()
        let discovery       = DiscoveryClient(config: config)
        enrollmentClient    = EnrollmentClient(config: config, discovery: discovery)
    }

    // MARK: - Enrollment

    /// Register this device with the IAM platform.
    ///
    /// Call once per key-pair lifecycle (first install, or after the user resets the app).
    /// On real devices the SDK calls App Attest internally; on simulators an empty attestation
    /// is sent — the server must have `SKIP_PLATFORM_ATTESTATION=true`.
    ///
    /// - Parameter enrollmentToken: ES256 JWT issued by your tenant backend containing
    ///   `device_id`, `customer_ref`, `tenant_id`, `challenge`, and `exp`.
    /// - Returns: `EnrollmentResult` — save `deviceId` and include it as `X-Device-ID`.
    @discardableResult
    public func enroll(enrollmentToken: String) async throws -> EnrollmentResult {
        let challenge = try extractChallenge(from: enrollmentToken)
        let deviceId  = try await deviceKeyManager.getOrCreateDeviceId()

        _ = try deviceKeyManager.ensureRsaKeyPair(deviceId: deviceId)
        let (modulus, exponent) = try deviceKeyManager.publicKeyComponents(deviceId: deviceId)

        let attestationData = try await deviceKeyManager.generateAttestation(
            keyId: deviceId,
            challenge: challenge
        )

        let sdkChecksum   = computeSdkChecksum()
        let sdkPublicKey  = try deviceKeyManager.sdkPublicKeyPem()
        let sdkSignature  = try deviceKeyManager.signSdkEnrollment(
            deviceId: deviceId, sdkVersion: SDK_VERSION, sdkChecksum: sdkChecksum
        )

        let response = try await enrollmentClient.attest(
            deviceId: deviceId,
            enrollmentToken: enrollmentToken,
            platform: "ios",
            attestation: attestationData.base64EncodedString(),
            keyAttestation: nil,
            publicKeyModulus: modulus,
            publicKeyExponent: exponent,
            sdkVersion: SDK_VERSION,
            sdkChecksum: sdkChecksum,
            sdkPublicKeyPem: sdkPublicKey,
            sdkSignature: sdkSignature
        )

        var workingKey = try deviceKeyManager.unwrapWorkingKey(
            deviceId: response.deviceId,
            wrappedKeyHex: response.wrappedWorkingKey
        )
        defer { workingKey.resetBytes(in: 0..<workingKey.count) }
        try workingKeyManager.store(deviceId: response.deviceId, workingKey: workingKey)

        if let encPublicKey = response.encPublicKey {
            encPublicKeyManager.store(deviceId: response.deviceId, pemPublicKey: encPublicKey)
        }

        return EnrollmentResult(deviceId: response.deviceId)
    }

    // MARK: - PIN capture (SDK-rendered overlay)

    /// Present a themed PIN entry overlay and return an encrypted ISO-0 PIN block.
    ///
    /// The raw PIN digits are handled entirely inside the SDK — they never pass through the
    /// host app's code. The overlay is dismissed automatically on confirm or cancel.
    ///
    /// - Parameters:
    ///   - viewController: The `UIViewController` to present the overlay from.
    ///   - pan: Primary Account Number (16–19 digits). Fetch from your backend immediately
    ///     before calling; do not store it in the app.
    ///   - theme: Optional visual configuration. Defaults to Chamsswitch brand colours.
    /// - Returns: `PinBlockResult` — forward `hex` or `base64` to your backend.
    @MainActor
    public func capturePIN(
        from viewController: UIViewController,
        pan: String,
        theme: PinTheme = PinTheme()
    ) async throws -> PinBlockResult {
        let pinVC = PinEntryViewController(theme: theme)
        viewController.present(pinVC, animated: true)

        var digits: [Character]
        do {
            digits = try await pinVC.awaitPin()
        } catch {
            pinVC.dismiss(animated: true)
            throw error
        }
        pinVC.dismiss(animated: true)

        let deviceId = try storedDeviceId()
        return try workingKeyManager.withKey(deviceId: deviceId) { workingKey in
            try pinBlockBuilder.build(pin: &digits, pan: pan, workingKey: workingKey)
        }
    }

    // MARK: - PIN block (low-level — use capturePIN instead)

    /// Encrypt a PIN block directly.
    ///
    /// Prefer `capturePIN(from:pan:theme:)` — that method renders a secure PIN entry overlay
    /// so the host app never handles raw digits. Use this method only if you control PIN
    /// collection through a custom accessibility flow.
    ///
    /// - Parameters:
    ///   - pan: Primary Account Number (16–19 digits).
    ///   - pin: PIN digits as a mutable `[Character]` array — zeroed on return.
    public func createPinBlock(pan: String, pin: inout [Character]) throws -> PinBlockResult {
        let deviceId = try storedDeviceId()
        return try workingKeyManager.withKey(deviceId: deviceId) { workingKey in
            try pinBlockBuilder.build(pin: &pin, pan: pan, workingKey: workingKey)
        }
    }

    // MARK: - PIN change

    /// Multi-step PIN change overlay — optional PAN collection, then old PIN → new PIN → confirm.
    ///
    /// **Virtual cards** (`pan` provided): goes straight to PIN entry.
    ///
    /// **Physical cards** (`maskedPan` provided): shows a PAN entry screen first so the
    /// cardholder can type the hidden digits from their physical card. The SDK reconstructs
    /// the full PAN internally before proceeding to PIN entry.
    ///
    /// After all steps the SDK builds ISO-0 blocks for both PINs and wraps the PAN with
    /// RSA-OAEP-SHA256 using the enc_public_key stored at enrollment.
    ///
    /// - Parameters:
    ///   - viewController: The `UIViewController` to present overlays from.
    ///   - pan:       Full card PAN (digits only, 12–19 chars). Use for virtual cards.
    ///   - maskedPan: Masked PAN where '*' marks hidden digits, e.g. "4111 **** **** 1234".
    ///                Use for physical cards — the SDK shows a digit-entry step first.
    ///   - theme:     Optional visual configuration.
    /// - Throws: `HashamMobileError.invalidPin("Cancelled")` if the user dismisses any screen.
    @MainActor
    public func changePIN(
        from viewController: UIViewController,
        pan:       String? = nil,
        maskedPan: String? = nil,
        theme:     PinTheme = PinTheme()
    ) async throws -> ChangePinResult {
        guard pan != nil || maskedPan != nil else {
            throw HashamMobileError.invalidInput("Either pan or maskedPan must be provided")
        }

        let resolvedPan: String
        if let pan = pan {
            resolvedPan = pan
        } else {
            resolvedPan = try await capturePhysicalPAN(from: viewController, maskedPan: maskedPan!, theme: theme)
        }

        var currentTheme = theme
        currentTheme.strings = PinTheme.Strings(title: "Enter your current PIN", subtitle: "")
        var oldDigits = try await captureStep(from: viewController, theme: currentTheme)

        do {
            var newDigits = try await captureNewPIN(from: viewController, theme: theme)
            let deviceId  = try storedDeviceId()
            return try workingKeyManager.withKey(deviceId: deviceId) { workingKey in
                let oldBlock   = try pinBlockBuilder.build(pin: &oldDigits, pan: resolvedPan, workingKey: workingKey)
                let newBlock   = try pinBlockBuilder.build(pin: &newDigits, pan: resolvedPan, workingKey: workingKey)
                let wrappedPan = try encPublicKeyManager.wrapPan(deviceId: deviceId, pan: resolvedPan)
                return ChangePinResult(
                    oldPinBlock: oldBlock.hex,
                    newPinBlock: newBlock.hex,
                    wrappedPan:  wrappedPan
                )
            }
        } catch {
            for i in 0..<oldDigits.count { oldDigits[i] = "0" }
            throw error
        }
    }

    @MainActor
    private func captureStep(from viewController: UIViewController, theme: PinTheme) async throws -> [Character] {
        let pinVC = PinEntryViewController(theme: theme)
        viewController.present(pinVC, animated: true)
        do {
            let digits = try await pinVC.awaitPin()
            pinVC.dismiss(animated: true)
            return digits
        } catch {
            pinVC.dismiss(animated: true)
            throw error
        }
    }

    @MainActor
    private func captureNewPIN(from viewController: UIViewController, theme: PinTheme) async throws -> [Character] {
        var mismatch = false
        while true {
            var attemptTheme = theme
            attemptTheme.strings = PinTheme.Strings(
                title:    "Enter your new PIN",
                subtitle: mismatch ? "PINs did not match — try again" : ""
            )
            var attempt = try await captureStep(from: viewController, theme: attemptTheme)

            var confirmTheme = theme
            confirmTheme.strings = PinTheme.Strings(title: "Confirm your new PIN", subtitle: "")

            do {
                var confirm = try await captureStep(from: viewController, theme: confirmTheme)
                if attempt == confirm {
                    for i in 0..<confirm.count { confirm[i] = "0" }
                    return attempt
                }
                for i in 0..<attempt.count { attempt[i] = "0" }
                for i in 0..<confirm.count { confirm[i] = "0" }
                mismatch = true
            } catch {
                for i in 0..<attempt.count { attempt[i] = "0" }
                throw error
            }
        }
    }

    @MainActor
    private func capturePhysicalPAN(
        from viewController: UIViewController,
        maskedPan: String,
        theme: PinTheme
    ) async throws -> String {
        let stripped = maskedPan.replacingOccurrences(of: " ", with: "")
        guard stripped.contains("*") else { return stripped }
        let panVC = PanEntryViewController(maskedPan: maskedPan, theme: theme)
        viewController.present(panVC, animated: true)
        do {
            let pan = try await panVC.awaitPan()
            panVC.dismiss(animated: true)
            return pan
        } catch {
            panVC.dismiss(animated: true)
            throw error
        }
    }

    // MARK: - Private helpers

    private func storedDeviceId() throws -> String {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: "com.chamsswitch.hasham",
            kSecAttrAccount as String: "device_id",
            kSecReturnData as String:  true,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let id = String(data: data, encoding: .utf8) else {
            throw HashamMobileError.notEnrolled
        }
        return id
    }

    private func extractChallenge(from token: String) throws -> String {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw HashamMobileError.invalidEnrollmentToken("Malformed JWT — expected 3 parts")
        }
        // JWT uses base64url without padding
        var padded = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 { padded += "=" }

        guard let data = Data(base64Encoded: padded),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let challenge = json["challenge"] as? String else {
            throw HashamMobileError.invalidEnrollmentToken("Missing or invalid 'challenge' claim")
        }
        return challenge
    }
}
