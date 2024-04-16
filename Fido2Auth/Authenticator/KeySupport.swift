//
//  KeySupport.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication

public protocol KeySupport {
    var selectedAlg: COSEAlgorithmIdentifier { get }
    func createKeyPair() -> Optional<COSEKey>
    func sign(data: [UInt8], context: LAContext) -> Optional<[UInt8]>
    func getPublicKey() throws -> SecKey
    func getPrivateKey() throws -> SecKey
    func deleteAllKeyPairs() -> Void
}

public class KeySupportChooser {
    
    public init() {}

    public func choose(_ requestedAlgorithms: [COSEAlgorithmIdentifier])
        -> Optional<KeySupport> {
        FidoLogger.debug("<KeySupportChooser> choose")

        for alg in requestedAlgorithms {
            switch alg {
            case COSEAlgorithmIdentifier.es256:
                return ECDSAKeySupport(alg: .es256)
            default:
                FidoLogger.debug("<KeySupportChooser> currently this algorithm not supported")
                return nil
            }
        }

        return nil
    }
}

public class ECDSAKeySupport : KeySupport {
    
    public let selectedAlg: COSEAlgorithmIdentifier
    
    init(alg: COSEAlgorithmIdentifier) {
        self.selectedAlg = alg
    }
    
    public func getPublicKey() throws -> SecKey{
        let keypairGenerator = KeyPair()
        return try keypairGenerator.getPublicKey()
    }
    
    public func getPrivateKey() throws -> SecKey{
        let keypairGenerator = KeyPair()
        return try keypairGenerator.getPrivateKey()
    }
    
    public func sign(data: [UInt8], context: LAContext) -> Optional<[UInt8]> {
        do {
            let keypairGenerator = KeyPair()
            keypairGenerator.setContext(context: context)
            let _ = try keypairGenerator.getPublicKey()
            let signature = try keypairGenerator.sign(Data(_:data), hash: .ecdsaSignatureMessageX962SHA256)
            return Array(signature)
        } catch let error {
            FidoLogger.debug("<ECDSAKeySupport> failed to sign: \(error)")
            return nil
        }
    }
    
    public func createKeyPair() -> Optional<COSEKey> {
        FidoLogger.debug("<ECDSAKeySupport> createKeyPair")
        do {
            let keypairGenerator = KeyPair()
            let pair = try keypairGenerator.generateAsymetricKeyPair()
            
            let publicKey = [UInt8](pair.public.DER)
            
            
//            var error:Unmanaged<CFError>?
//            guard let cfdata = SecKeyCopyExternalRepresentation(pair.public, &error) else {
//                return nil
//            }
//            let data:Data = cfdata as Data
//            let p256PublicKey = try P256.Signing.PublicKey(x963Representation: data)
//            let publicKey = p256PublicKey.derRepresentation
//            
            if publicKey.count != 91 {
                FidoLogger.debug("<ECDSAKeySupport> length of pubKey should be 91: \(publicKey.count)")
                return nil
            }
            
            let x = Array(publicKey[27..<59])
            let y = Array(publicKey[59..<91])
            
            let key: COSEKey = COSEKeyEC2(
                alg: self.selectedAlg.rawValue,
                crv: COSEKeyCurveType.p256,
                xCoord: x,
                yCoord: y
            )
            return key
            
        } catch let error {
            FidoLogger.debug("<ECDSAKeySupport> failed to create key-pair: \(error)")
            return nil
        }
    }
    
    public func deleteAllKeyPairs() {
        let keypairGenerator = KeyPair()
        keypairGenerator.deleteKeychainItem()
    }
}
