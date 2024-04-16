//
//  Authenticator.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication

public protocol Authenticator {

    var attachment: AuthenticatorAttachment { get }
    var transport: AuthenticatorTransport { get }
    
    var counterStep: UInt32 { set get }
    var allowResidentKey: Bool { get }
    var allowUserVerification: Bool { get }
    
    func newMakeCredentialSession(context: LAContext?) -> AuthenticatorMakeCredentialSession
    func newGetAssertionSession(context: LAContext?) -> AuthenticatorGetAssertionSession

}

public protocol AuthenticatorMakeCredentialSession {
    
    var attachment: AuthenticatorAttachment { get }
    var transport: AuthenticatorTransport { get }
    
    var delegate: AuthenticatorMakeCredentialSessionDelegate? { set get }

    func makeCredential(
        hash:                            [UInt8],
        rpEntity:                        PublicKeyCredentialRpEntity,
        userEntity:                      PublicKeyCredentialUserEntity,
        requireResidentKey:              Bool,
        requireUserPresence:             Bool,
        requireUserVerification:         Bool,
        credTypesAndPubKeyAlgs:          [PublicKeyCredentialParameters],
        excludeCredentialDescriptorList: [PublicKeyCredentialDescriptor]
    ) async
    
    func canPerformUserVerification() -> Bool
    func canStoreResidentKey() -> Bool
    
    func start()
    func cancel(reason: FidoError)

}

public protocol AuthenticatorGetAssertionSession {
    
    var attachment: AuthenticatorAttachment { get }
    var transport: AuthenticatorTransport { get }
    
    var delegate: AuthenticatorGetAssertionSessionDelegate? { set get }
    
    func getAssertion(
        rpId: String,
        hash:                          [UInt8],
        allowCredentialDescriptorList: [PublicKeyCredentialDescriptor],
        requireUserPresence:           Bool,
        requireUserVerification:       Bool
    )
    
    func canPerformUserVerification() -> Bool
    
    func start()
    func cancel(reason: FidoError)

}

public protocol AuthenticatorMakeCredentialSessionDelegate {
    func authenticatorSessionDidBecomeAvailable(session: AuthenticatorMakeCredentialSession) async
    func authenticatorSessionDidBecomeUnavailable(session: AuthenticatorMakeCredentialSession)
    func authenticatorSessionDidStopOperation(session: AuthenticatorMakeCredentialSession, reason: FidoError)
    func authenticatorSessionDidMakeCredential(session: AuthenticatorMakeCredentialSession, attestation: AttestationObject)
}

public protocol AuthenticatorGetAssertionSessionDelegate {
    func authenticatorSessionDidBecomeAvailable(session: AuthenticatorGetAssertionSession)
    func authenticatorSessionDidBecomeUnavailable(session: AuthenticatorGetAssertionSession)
    func authenticatorSessionDidStopOperation(session: AuthenticatorGetAssertionSession, reason: FidoError)
    func authenticatorSessionDidDiscoverCredential(session: AuthenticatorGetAssertionSession, assertion: AuthenticatorAssertionResult)
}

public struct AuthenticatorAssertionResult {
    var credentailId: [UInt8]?
    var userHandle: [UInt8]?
    var signature: [UInt8]
    var authenticatorData: [UInt8]
    init(authenticatorData: [UInt8], signature: [UInt8]) {
        self.authenticatorData = authenticatorData
        self.signature = signature
    }
}
