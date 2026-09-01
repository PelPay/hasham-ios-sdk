import Foundation

internal final class DiscoveryClient {

    struct Doc: Sendable {
        let attestationEndpoint: String
    }

    private let config: HashamMobileConfig
    private var cached: Doc?

    init(config: HashamMobileConfig) {
        self.config = config
    }

    func discover() async throws -> Doc {
        if let cached = cached { return cached }

        guard let url = URL(string: config.discoveryUrl) else {
            throw HashamMobileError.networkError("Invalid discovery URL: \(config.discoveryUrl)")
        }
        var request = URLRequest(url: url, timeoutInterval: config.timeoutSeconds)
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw HashamMobileError.networkError("Discovery fetch failed: \(error.localizedDescription)")
        }

        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw HashamMobileError.networkError("Discovery returned non-200 response")
        }

        guard
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let endpoint = json["attestation_endpoint"] as? String
        else {
            throw HashamMobileError.networkError("Discovery doc missing attestation_endpoint")
        }

        let doc = Doc(attestationEndpoint: endpoint)
        cached = doc
        return doc
    }
}
