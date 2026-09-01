import Foundation
import CommonCrypto

/// Builds an ISO 9564-1 Format 0 PIN block and encrypts it under the working key.
///
/// Algorithm selection:
/// - 16-byte key → 3DES-2K (extended to 24 bytes) → 8-byte output
/// - 24-byte key → 3DES-3K                         → 8-byte output
/// - 32-byte key → AES-256-ECB (zero-padded input) → 16-byte output
internal struct PinBlockBuilder {

    func build(pin: inout [Character], pan: String, workingKey: Data) throws -> PinBlockResult {
        defer { for i in 0..<pin.count { pin[i] = "0" } }

        guard pin.count >= 4 && pin.count <= 12 else {
            throw HashamMobileError.invalidPin("PIN must be 4–12 digits")
        }
        guard pin.allSatisfy({ $0.isNumber }) else {
            throw HashamMobileError.invalidPin("PIN must contain only digits")
        }

        let pinBlock = buildPinBlock(pin)
        let panBlock = try buildPanBlock(pan)
        let xored    = Data(zip(pinBlock, panBlock).map { $0 ^ $1 })
        return PinBlockResult(encryptedBlock: try encrypt(xored, workingKey: workingKey))
    }

    // MARK: - Block construction

    private func buildPinBlock(_ pin: [Character]) -> Data {
        var hex = "0" + String(format: "%X", pin.count)
        for c in pin { hex += String(c) }
        while hex.count < 16 { hex += "F" }
        return Data(hexString: hex)
    }

    private func buildPanBlock(_ pan: String) throws -> Data {
        let digits = pan.filter { $0.isNumber }
        guard digits.count >= 13 else {
            throw HashamMobileError.invalidInput("PAN must have at least 13 digits")
        }
        // rightmost 12 digits excluding the check digit
        let inner = String(digits.dropLast().suffix(12))
        let padded = inner.count < 12
            ? String(repeating: "0", count: 12 - inner.count) + inner
            : inner
        return Data(hexString: "0000" + padded)
    }

    // MARK: - Encryption

    private func encrypt(_ block: Data, workingKey: Data) throws -> Data {
        switch workingKey.count {
        case 16:
            var key24 = Data(workingKey)
            key24.append(workingKey.prefix(8))
            return try tripleDesEcb(block, key: key24)
        case 24:
            return try tripleDesEcb(block, key: workingKey)
        case 32:
            // AES block = 16 bytes; zero-pad the 8-byte ISO-0 block
            var padded = Data(block)
            padded.append(Data(count: 16 - block.count))
            return try aesEcb(padded, key: workingKey)
        default:
            throw HashamMobileError.encryptionFailed("Unsupported key length: \(workingKey.count)")
        }
    }

    private func tripleDesEcb(_ data: Data, key: Data) throws -> Data {
        var output = [UInt8](repeating: 0, count: data.count)
        var written = 0
        let status = data.withUnsafeBytes { dataPtr in
            key.withUnsafeBytes { keyPtr in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithm3DES),
                    CCOptions(kCCOptionECBMode),
                    keyPtr.baseAddress, kCCKeySize3DES,
                    nil,
                    dataPtr.baseAddress, data.count,
                    &output, output.count,
                    &written
                )
            }
        }
        guard status == kCCSuccess else {
            throw HashamMobileError.encryptionFailed("3DES-ECB failed: \(status)")
        }
        return Data(output.prefix(written))
    }

    private func aesEcb(_ data: Data, key: Data) throws -> Data {
        var output = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var written = 0
        let status = data.withUnsafeBytes { dataPtr in
            key.withUnsafeBytes { keyPtr in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyPtr.baseAddress, key.count,
                    nil,
                    dataPtr.baseAddress, data.count,
                    &output, output.count,
                    &written
                )
            }
        }
        guard status == kCCSuccess else {
            throw HashamMobileError.encryptionFailed("AES-ECB failed: \(status)")
        }
        return Data(output.prefix(written))
    }
}
