//
//  AuthenticatorGetCredentialsSession.swift
//  custom-fido-app
//
//  Created by Antonio Alanya on 3/04/24.
//

import Foundation
import LocalAuthentication
import CryptoKit

public class AuthenticatorGetCredentialsAssertionSession : AuthenticatorGetAssertionSession {
    
    public var delegate : AuthenticatorGetAssertionSessionDelegate?
    
    private let setting: InternalAuthenticatorSetting
    
    public var attachment: AuthenticatorAttachment {
        get {
            return self.setting.attachment
        }
    }
    
    public var transport: AuthenticatorTransport {
        get {
            return self.setting.transport
        }
    }
    
    private let credentialStore:   CredentialStore
    private let keySupportChooser: KeySupportChooser
    private let context:           LAContext
    
    private var started = false
    private var stopped = false
    
    init(
        setting:             InternalAuthenticatorSetting,
        credentialStore:     CredentialStore,
        keySupportChooser:   KeySupportChooser,
        context:             LAContext? = nil
    ) {
        self.setting             = setting
        self.credentialStore     = credentialStore
        self.keySupportChooser   = keySupportChooser
        self.context             = context ?? LAContext()
    }
    
    public func start() {
        FidoLogger.debug("<GetAssertionSession> start")
        if self.stopped {
            FidoLogger.debug("<GetAssertionSession> alread stopped")
            return
        }
        if self.started {
            FidoLogger.debug("<GetAssertionSession> alread started")
            return
        }
        self.started = true
        self.delegate?.authenticatorSessionDidBecomeAvailable(session: self)
    }
    
    public func canPerformUserVerification() -> Bool {
        return self.setting.allowUserVerification
    }
    
    public func cancel(reason: FidoError) {
        FidoLogger.debug("<GetAssertionSession> cancel")
        if self.stopped {
            FidoLogger.debug("<GetAssertionSession> already stopped")
            return
        } else {
            FidoLogger.debug("<GetAssertionSession> stop by clientCancelled")
            self.stop(by: reason)
        }
    }
    
    private func stop(by reason: FidoError) {
        FidoLogger.debug("<GetAssertionSession> stop")
        if !self.started {
            FidoLogger.debug("<GetAssertionSession> not started")
            return
        }
        if self.stopped  {
            FidoLogger.debug("<GetAssertionSession> already stopped")
            return
        }
        self.stopped = true
        self.delegate?.authenticatorSessionDidStopOperation(
            session: self,
            reason:  reason
        )
    }
    
    private func completed() {
        self.stopped = true
    }
    
    public func getAssertion(
        rpId:                          String,
        hash:                          [UInt8],
        allowCredentialDescriptorList: [PublicKeyCredentialDescriptor],
        requireUserPresence:           Bool,
        requireUserVerification:       Bool
    ) {
        do{
            FidoLogger.debug("<GetAssertionSession> get assertion")

            let credSources =
            try self.gatherCredentialSources(
                rpId:                          rpId,
                allowCredentialDescriptorList: allowCredentialDescriptorList
            )
            
            if credSources.isEmpty {
                let keychain = KeyPair()
                FidoLogger.debug("<GetAssertion> not found allowable credential source, stop session")
                self.stop(by: FidoError.noCredentials)
                return
            }
            
            let cred = credSources[0];
            var newSignCount: UInt32 = 0
            
            var copiedCred = cred
            copiedCred.signCount = cred.signCount + self.setting.counterStep
            newSignCount = copiedCred.signCount
            if !self.credentialStore.saveCredentialSource(copiedCred) {
                self.stop(by: FidoError.unknown)
                return
            }
            
            let extensions = SimpleOrderedDictionary<String>()
            
            let authenticatorData = AuthenticatorData(
                rpIdHash:               [UInt8](SHA256.hash(data: Data(rpId.utf8))),
                userPresent:            (requireUserPresence || requireUserVerification),
                userVerified:           requireUserVerification,
                signCount:              newSignCount,
                attestedCredentialData: nil,
                extensions:             extensions
            )
            
            let authenticatorDataBytes = authenticatorData.toBytes()
            
            var data = authenticatorDataBytes
            data.append(contentsOf: hash)

            guard let alg = COSEAlgorithmIdentifier.fromInt(cred.alg) else {
                FidoLogger.debug("<GetAssertion> insufficient capability (alg), stop session")
                self.stop(by: FidoError.unsupported)
                return
            }
            
            guard let keySupport =
                    self.keySupportChooser.choose([alg]) else {
                FidoLogger.debug("<GetAssertion> insufficient capability (alg), stop session")
                self.stop(by: FidoError.unsupported)
                return
            }
            
            guard let signature = keySupport.sign(data: data, context: self.context) else {
                self.stop(by: FidoError.unknown)
                return
            }
            
            var assertion = AuthenticatorAssertionResult(
                authenticatorData: authenticatorDataBytes,
                signature:         signature
            )
            
            assertion.userHandle = cred.userHandle
            
            if allowCredentialDescriptorList.count != 1 {
                assertion.credentailId = cred.id
            }
            
            self.completed()
            self.delegate?.authenticatorSessionDidDiscoverCredential(
                session:   self,
                assertion: assertion
            )
        } catch let error {
            print(error)
            if let authError = error as? FidoError {
                self.stop(by: authError)
            }else{
                self.stop(by: .unknown)
            }
        }
    }
    
    private func gatherCredentialSources(
        rpId: String,
        allowCredentialDescriptorList: [PublicKeyCredentialDescriptor]
    ) throws -> [PublicKeyCredentialSource] {
        
        if allowCredentialDescriptorList.isEmpty {
            return try self.credentialStore.loadAllCredentialSources(rpId: rpId)
        } else {
            return allowCredentialDescriptorList.compactMap {
                return self.credentialStore.lookupCredentialSource(
                    rpId:         rpId,
                    credentialId: $0.id
                )
            }
        }
    }
}
