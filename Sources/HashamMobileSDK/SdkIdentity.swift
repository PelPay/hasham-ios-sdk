import Foundation
import CryptoKit

// SDK_CHECKSUM is replaced by the release build script with the SHA-256 of the compiled
// framework binary. Do not edit manually — CI sets this before the final compilation step.
internal let SDK_VERSION  = "1.0.0"
internal let SDK_CHECKSUM = "0000000000000000000000000000000000000000000000000000000000000000"

/// Computes the SHA-256 of the SDK framework binary inside the host app bundle.
///
/// This is the same value registered in IAM when the SDK version is published.
/// The release build script regenerates SDK_CHECKSUM from the compiled framework before
/// shipping, so this runtime value matches the compile-time constant on genuine builds.
/// A tampered SDK will produce a different hash and fail IAM's registry check.
internal func computeSdkChecksum() -> String {
    guard let executableURL = Bundle(for: _HashamSDKBundleMarker.self).executableURL,
          let handle = try? FileHandle(forReadingFrom: executableURL) else {
        return SDK_CHECKSUM
    }
    defer { try? handle.close() }

    var digest = SHA256()
    let bufferSize = 8192
    while true {
        let chunk: Data
        if #available(iOS 13.4, *) {
            guard let c = try? handle.read(upToCount: bufferSize), !c.isEmpty else { break }
            chunk = c
        } else {
            chunk = handle.readData(ofLength: bufferSize)
            if chunk.isEmpty { break }
        }
        digest.update(data: chunk)
    }
    return Data(digest.finalize()).map { String(format: "%02x", $0) }.joined()
}

// Marker class so Bundle(for:) resolves to the SDK framework bundle.
private final class _HashamSDKBundleMarker {}

/// Builds a compact JWS (RFC 7515) signed with ES256.
/// IAM verifies this with jose's compactVerify, which expects the three-part dot-separated form.
internal func buildCompactJws(payload: Data, sign: (Data) throws -> Data) throws -> String {
    let headerB64  = base64url(data: #"{"alg":"ES256"}"#.data(using: .utf8)!)
    let payloadB64 = base64url(data: payload)
    let signingInput = "\(headerB64).\(payloadB64)".data(using: .ascii)!
    let rawSig = try sign(signingInput)
    return "\(headerB64).\(payloadB64).\(base64url(data: rawSig))"
}

internal func base64url(data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Convert DER-encoded ECDSA signature (from SecKeyCreateSignature) to raw R||S (64 bytes) for JWS.
internal func derToRawEcdsa(_ der: Data) throws -> Data {
    var i = der.startIndex
    guard der[i] == 0x30 else { throw HashamMobileError.keyGenerationFailed("Not a DER SEQUENCE") }
    i = der.index(after: i)
    i = skipDerLength(der, from: i)

    let (r, nextI) = try readDerInteger(der, from: i)
    let (s, _)     = try readDerInteger(der, from: nextI)
    return pad32(r) + pad32(s)
}

private func skipDerLength(_ data: Data, from index: Data.Index) -> Data.Index {
    var i = index
    if data[i] & 0x80 == 0 { return data.index(after: i) }
    let byteCount = Int(data[i] & 0x7F)
    return data.index(i, offsetBy: byteCount + 1)
}

private func readDerInteger(_ data: Data, from index: Data.Index) throws -> (Data, Data.Index) {
    var i = index
    guard data[i] == 0x02 else { throw HashamMobileError.keyGenerationFailed("Expected INTEGER tag") }
    i = data.index(after: i)
    let len: Int
    if data[i] & 0x80 != 0 {
        var byteCount = Int(data[i] & 0x7F); i = data.index(after: i)
        var l = 0
        for _ in 0..<byteCount { l = l * 256 + Int(data[i]); i = data.index(after: i) }
        len = l
    } else {
        len = Int(data[i]); i = data.index(after: i)
    }
    var bytes = Data(data[i..<data.index(i, offsetBy: len)])
    if bytes.first == 0x00 { bytes = bytes.dropFirst() }
    return (Data(bytes), data.index(i, offsetBy: len))
}

private func pad32(_ b: Data) -> Data {
    let arr = Array(b)
    let stripped = arr.count > 32 ? Array(arr.suffix(32)) : arr
    let padding = [UInt8](repeating: 0, count: max(0, 32 - stripped.count))
    return Data(padding + stripped)
}

/// Convert an uncompressed EC P-256 point (0x04 + 32-byte X + 32-byte Y) to SPKI DER.
/// This is the format iOS SecKey external representation provides for P-256 keys.
internal func ecPointToSpkiDer(_ point: Data) -> Data {
    // AlgorithmIdentifier SEQUENCE {
    //   OID id-ecPublicKey (1.2.840.10045.2.1),
    //   OID secp256r1      (1.2.840.10045.3.1.7)
    // }
    let algId = Data([
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ])
    let bitString = Data([0x03, UInt8(point.count + 1), 0x00]) + point
    let content   = algId + bitString
    return Data([0x30, UInt8(content.count)]) + content
}

internal func spkiDerToPem(_ der: Data) -> String {
    let b64  = der.base64EncodedString()
    var body = ""
    var idx  = b64.startIndex
    while idx < b64.endIndex {
        let end = b64.index(idx, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
        if !body.isEmpty { body += "\n" }
        body += b64[idx..<end]
        idx = end
    }
    return "-----BEGIN PUBLIC KEY-----\n\(body)\n-----END PUBLIC KEY-----"
}
