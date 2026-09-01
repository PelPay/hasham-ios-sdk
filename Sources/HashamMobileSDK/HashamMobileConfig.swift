import Foundation

public struct HashamMobileConfig: Sendable {
    /// Discovery document URL, e.g. "https://api.chamsswitch.com/auth/.well-known/mobile-sdk"
    public let discoveryUrl: String
    public let timeoutSeconds: TimeInterval

    public init(
        discoveryUrl: String = HashamMobileConfig.defaultDiscoveryUrl,
        timeoutSeconds: TimeInterval = 30
    ) {
        self.discoveryUrl = discoveryUrl
        self.timeoutSeconds = timeoutSeconds
    }

    public static let defaultDiscoveryUrl =
        "https://api.chamsswitch.com/auth/.well-known/mobile-sdk"
}
