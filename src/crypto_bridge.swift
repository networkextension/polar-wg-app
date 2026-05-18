import Foundation
import CryptoKit

// ─────────────────────────────────────────────────────────────────────────
// CryptoKit Curve25519 bridge.
//
// @_cdecl exports C-linkage symbols that libwg.a calls through the
// crypto/curve25519.h stubs.
//
// KEY DESIGN DECISION: noise_create_initiation calls
//   curve25519_generate_secret → curve25519_generate_public
// in sequence on the SAME raw byte buffer. A naïve implementation would
// generate → export rawRepresentation → re-import PrivateKey(rawRep:).
// But CryptoKit's rawRepresentation ↔ PrivateKey(rawRep:) round-trip
// OCCASIONALLY fails — CryptoKit may apply internal validation or
// re-clamping that rejects bytes it originally produced.
//
// Fix: we cache the last CryptoKit PrivateKey object from
// curve25519_generate_secret. When curve25519_generate_public is called
// with the same bytes, we use the cached object directly instead of
// re-importing. This eliminates the round-trip failure entirely.
// ─────────────────────────────────────────────────────────────────────────

// Thread-local cache for the generate_secret → generate_public pair.
// Safe because WireGuard's noise_create_initiation calls them in
// strict sequence on a single thread (the wg_session_tick / kick path).
private var _cachedPrivKey: Curve25519.KeyAgreement.PrivateKey?
private var _cachedRawBytes: [UInt8]?

@_cdecl("curve25519")
public func curve25519(
    out: UnsafeMutablePointer<UInt8>,
    privateKey: UnsafePointer<UInt8>,
    publicKey: UnsafePointer<UInt8>
) -> Int32 {
    do {
        let priv = try resolvePrivateKey(privateKey)
        let pub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(bytes: publicKey, count: 32)
        )
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        shared.withUnsafeBytes { ptr in
            out.initialize(
                from: ptr.bindMemory(to: UInt8.self).baseAddress!, count: 32
            )
        }
        return 1
    } catch {
        return 0
    }
}

@_cdecl("curve25519_generate_public")
public func curve25519_generate_public(
    out: UnsafeMutablePointer<UInt8>,
    privateKey: UnsafePointer<UInt8>
) -> Int32 {
    do {
        let priv = try resolvePrivateKey(privateKey)
        let pub = priv.publicKey
        pub.rawRepresentation.withUnsafeBytes { ptr in
            out.initialize(
                from: ptr.bindMemory(to: UInt8.self).baseAddress!, count: 32
            )
        }
        return 1
    } catch {
        return 0
    }
}

@_cdecl("curve25519_generate_secret")
public func curve25519_generate_secret(
    out: UnsafeMutablePointer<UInt8>
) {
    let priv = Curve25519.KeyAgreement.PrivateKey()
    let raw = Array(priv.rawRepresentation)
    for i in 0..<32 { out[i] = raw[i] }
    // Cache so the subsequent generate_public call can reuse
    // the original CryptoKit object without re-importing raw bytes.
    _cachedPrivKey = priv
    _cachedRawBytes = raw
}

@_cdecl("curve25519_clamp_secret")
public func curve25519_clamp_secret(
    secret: UnsafeMutablePointer<UInt8>
) {
    secret[0] &= 248
    secret[31] &= 127
    secret[31] |= 64
}

// MARK: - Internal

/// Resolve raw private key bytes to a CryptoKit PrivateKey object.
/// Uses the cache if the bytes match the last generate_secret output;
/// otherwise falls back to PrivateKey(rawRepresentation:).
private func resolvePrivateKey(
    _ rawPtr: UnsafePointer<UInt8>
) throws -> Curve25519.KeyAgreement.PrivateKey {
    let inBytes = Array(UnsafeBufferPointer(start: rawPtr, count: 32))

    // Fast path: same bytes we just generated → use cached object.
    if let cached = _cachedPrivKey,
       let cachedRaw = _cachedRawBytes,
       cachedRaw == inBytes {
        return cached
    }

    // Slow path: re-import from raw bytes.
    return try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(inBytes)
    )
}
