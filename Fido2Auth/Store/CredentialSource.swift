//
//  CredentialSource.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation

public struct PublicKeyCredentialSource {
    
    public var keyLabel: String {
        get {
          let userHex = self.userHandle.map { String(format: "%02x", $0) }.joined()
          return "\(self.rpId)/\(userHex)"
        }
    }
    
    var type:       PublicKeyCredentialType = .publicKey
    var signCount:  UInt32 = 0
    var id:         [UInt8] // credential id
    var rpId:       String
    var userHandle: [UInt8]
    var alg:        Int = COSEAlgorithmIdentifier.rs256.rawValue
    
    init(
        id:         [UInt8],
        rpId:       String,
        userHandle: [UInt8],
        signCount:  UInt32,
        alg:        Int
        ) {
        
        self.id         = id
        self.rpId       = rpId
        self.userHandle = userHandle
        self.signCount  = signCount
        self.alg        = alg
    }
    
    public func toCBOR() -> Optional<[UInt8]> {
        FidoLogger.debug("<PublicKeyCredentialSource> toCBOR")
        
        let builder = CBORWriter()
        
        let dict = SimpleOrderedDictionary<String>()
        
        dict.addBytes("id", self.id)
        dict.addString("rpId", self.rpId)
        dict.addBytes("userHandle", self.userHandle)
        dict.addInt("alg", Int64(self.alg))
        dict.addInt("signCount", Int64(self.signCount))
        return builder.putStringKeyMap(dict).getResult()
    }
    
    public static func fromCBOR(_ bytes: [UInt8]) -> Optional<PublicKeyCredentialSource> {
        FidoLogger.debug("<PublicKeyCredentialSource> fromCBOR")
        
        var id:         [UInt8]
        var rpId:       String = ""
        var userHandle: [UInt8]
        var algId:      Int = 0
        var signCount:  UInt32 = 0
        
        guard let dict = CBORReader(bytes: bytes).readStringKeyMap()  else {
            return nil
        }
        
        if let foundId = dict["id"] as? [UInt8] {
            id = foundId
        } else {
            FidoLogger.debug("<PublicKeyCredentialSource> id not found")
            return nil
        }
        
        if let foundSignCount = dict["signCount"] as? Int64 {
            signCount = UInt32(foundSignCount)
        } else {
            FidoLogger.debug("<PublicKeyCredentialSource> signCount not found")
            return nil
        }
        
        if let foundRpId = dict["rpId"] as? String {
            rpId = foundRpId
        } else {
            FidoLogger.debug("<PublicKeyCredentialSource> rpId not found")
            return nil
        }
        
        if let handle = dict["userHandle"] as? [UInt8] {
            userHandle = handle
        } else {
            FidoLogger.debug("<PublicKeyCredentialSource> userHandle not found")
            return nil
        }
        
        if let alg = dict["alg"] as? Int64 {
            algId = Int(alg)
        } else {
            FidoLogger.debug("<PublicKeyCredentialSource> alg not found")
            return nil
        }
        
        let src = PublicKeyCredentialSource(
            id:         id,
            rpId:       rpId,
            userHandle: userHandle,
            signCount:  signCount,
            alg:        algId
        )
        return src
    }
}
