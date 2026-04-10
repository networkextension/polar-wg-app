import Foundation
import CryptoKit

// 使用 @_cdecl 强制编译器生成 libwg.a 寻找的 C 符号名
@_cdecl("curve25519")
public func curve25519(out: UnsafeMutablePointer<UInt8>, privateKey: UnsafePointer<UInt8>, publicKey: UnsafePointer<UInt8>) -> Int32 {
    let privData = Data(bytes: privateKey, count: 32)
    let pubData = Data(bytes: publicKey, count: 32)
    
    do {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privData)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubData)
        
        // 计算共享密钥 (DH)
        let sharedSecret = try priv.sharedSecretFromKeyAgreement(with: pub)
        
        // 将结果拷贝到输出缓冲区
        sharedSecret.withUnsafeBytes { ptr in
            out.initialize(from: ptr.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        return 1
    } catch {
        return 0
    }
}

@_cdecl("curve25519_generate_public")
public func curve25519_generate_public(out: UnsafeMutablePointer<UInt8>, privateKey: UnsafePointer<UInt8>) -> Int32 {
    let privData = Data(bytes: privateKey, count: 32)
    if let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privData) {
        let pub = priv.publicKey
        pub.rawRepresentation.withUnsafeBytes { ptr in
            out.initialize(from: ptr.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        return 1
    }
    return 0
}

@_cdecl("curve25519_generate_secret")
public func curve25519_generate_secret(out: UnsafeMutablePointer<UInt8>) {
    let priv = Curve25519.KeyAgreement.PrivateKey()
    priv.rawRepresentation.withUnsafeBytes { ptr in
        out.initialize(from: ptr.bindMemory(to: UInt8.self).baseAddress!, count: 32)
    }
}

// 注意：WireGuard 通常对私钥有 "clamping" 要求
@_cdecl("curve25519_clamp_secret")
public func curve25519_clamp_secret(secret: UnsafeMutablePointer<UInt8>) {
    secret[0] &= 248
    secret[31] &= 127
    secret[31] |= 64
}
