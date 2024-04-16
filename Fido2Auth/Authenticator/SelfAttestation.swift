//
//  SelfAttestation.swift
//  matrix
//
//  Created by Antonio Alanya on 1/04/24.
//

import Foundation
import LocalAuthentication

public class SelfAttestation {
    
    public static func create(
        authData:       AuthenticatorData,
        clientDataHash: [UInt8],
        alg:            COSEAlgorithmIdentifier,
        keyLabel:       String,
        context:        LAContext
        ) -> Optional<AttestationObject> {
        
        FidoLogger.debug("<SelfAttestation> create")
        
        var dataToBeSigned = authData.toBytes()
        dataToBeSigned.append(contentsOf: clientDataHash)
        
        guard let keySupport =
            KeySupportChooser().choose([alg]) else {
                FidoLogger.debug("<SelfAttestation> key-support not found")
                return nil
        }
        
        guard let sig = keySupport.sign(
            data:  dataToBeSigned,
            context: context
        ) else {
            FidoLogger.debug("<AttestationHelper> failed to sign")
            return nil
        }
        
        let stmt = SimpleOrderedDictionary<String>()
        stmt.addInt("alg", Int64(alg.rawValue))
        stmt.addBytes("sig", sig)
        
        return AttestationObject(
            fmt:      "packed",
            authData: authData,
            attStmt:  stmt
        )
    }

    
}
