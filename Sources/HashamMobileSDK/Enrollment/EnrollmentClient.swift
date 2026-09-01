import Foundation

internal struct EnrollmentClient {

    private let discovery: DiscoveryClient
    private let timeoutSeconds: TimeInterval

    init(config: HashamMobileConfig, discovery: DiscoveryClient) {
        self.discovery = discovery
        self.timeoutSeconds = config.timeoutSeconds
    }

    struct Response {
        let deviceId: String
        let wrappedWorkingKey: String
        let encPublicKey: String?
    }

    func attest(
        deviceId: String,
        enrollmentToken: String,
        platform: String,
        attestation: String,
        keyAttestation: String?,
        publicKeyModulus: String,
        publicKeyExponent: String,
        sdkVersion: String,
        sdkChecksum: String,
        sdkPublicKeyPem: String,
        sdkSignature: String
    ) async throws -> Response {

        var body: [String: Any] = [
            "device_id":        deviceId,
            "enrollment_token": enrollmentToken,
            "platform":         platform,
            "attestation":      attestation,
            "public_key": [
                "modulus":  publicKeyModulus,
                "exponent": publicKeyExponent,
            ],
            "sdk_version":    sdkVersion,
            "sdk_checksum":   sdkChecksum,
            "sdk_public_key": sdkPublicKeyPem,
            "sdk_signature":  sdkSignature,
        ]
        if let chain = keyAttestation { body["key_attestation"] = chain }

        let discovered = try await discovery.discover()
        guard let url = URL(string: discovered.attestationEndpoint) else {
            throw HashamMobileError.networkError("Invalid attestation endpoint from discovery")
        }
        var request = URLRequest(url: url, timeoutInterval: timeoutSeconds)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw HashamMobileError.networkError(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw HashamMobileError.networkError("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let code = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String ?? "UNKNOWN"
            throw HashamMobileError.enrollmentFailed(http.statusCode, code)
        }

        guard
            let json       = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let retId      = json["device_id"] as? String,
            let wrappedKey = json["wrapped_working_key"] as? String
        else {
            throw HashamMobileError.networkError("Unexpected response body")
        }

        return Response(
            deviceId:         retId,
            wrappedWorkingKey: wrappedKey,
            encPublicKey:     json["enc_public_key"] as? String
        )
    }
}
