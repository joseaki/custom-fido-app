//
//  AuthenticatorCreateCredentials.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication
import CryptoKit

@available(iOS 13.0, *)
public class AuthenticatorCreateCredentialsSession : AuthenticatorMakeCredentialSession {
    public var delegate: AuthenticatorMakeCredentialSessionDelegate?
    
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
        setting:           InternalAuthenticatorSetting,
        credentialStore:   CredentialStore,
        keySupportChooser: KeySupportChooser,
        context:           LAContext? = nil
    ) {
        self.setting           = setting
        self.credentialStore   = credentialStore
        self.keySupportChooser = keySupportChooser
        self.context           = context ?? LAContext()
    }
    
    public func canPerformUserVerification() -> Bool {
        return self.setting.allowUserVerification
    }
    
    public func canStoreResidentKey() -> Bool {
        return true
    }
    
    public func start() {
        if self.stopped {
            FidoLogger.debug("<MakeCredentialSession> already stopped")
            return
        }
        if self.started {
            FidoLogger.debug("<MakeCredentialSession> already started")
            return
        }
        self.started = true
        Task{
            await self.delegate?.authenticatorSessionDidBecomeAvailable(session: self)
        }
        
    }
    
    public func cancel(reason: FidoError) {
        FidoLogger.debug("<MakeCredentialSession> cancel")
        if self.stopped {
            FidoLogger.debug("<MakeCredentialSession> already stopped")
            return
        }
        else {
            self.stop(by: reason)
        }
    }
    
    private func stop(by reason: FidoError) {
        if !self.started {
            return
        }
        if self.stopped  {
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
    
    private func createNewCredentialId() -> [UInt8] {
        return UUIDHelper.toBytes(UUID())
    }
    
    public func makeCredential(
        hash: [UInt8],
        rpEntity: PublicKeyCredentialRpEntity,
        userEntity: PublicKeyCredentialUserEntity,
        requireResidentKey: Bool,
        requireUserPresence: Bool,
        requireUserVerification: Bool,
        credTypesAndPubKeyAlgs: [PublicKeyCredentialParameters],
        excludeCredentialDescriptorList: [PublicKeyCredentialDescriptor]
    ) {
        FidoLogger.debug("")
    }

    public func makeCredential(
        hash:                            [UInt8],// hash of ClientData
        rpEntity:                        PublicKeyCredentialRpEntity,
        userEntity:                      PublicKeyCredentialUserEntity,
        requireResidentKey:              Bool,
        requireUserPresence:             Bool,
        requireUserVerification:         Bool,
        credTypesAndPubKeyAlgs:          [PublicKeyCredentialParameters] = [PublicKeyCredentialParameters](),
        excludeCredentialDescriptorList: [PublicKeyCredentialDescriptor] = [PublicKeyCredentialDescriptor]()
    ) async {
        
        FidoLogger.debug("<MakeCredentialSession> make credential")
        
        let requestedAlgs = credTypesAndPubKeyAlgs.map { $0.alg }
        
        guard let keySupport =
                self.keySupportChooser.choose(requestedAlgs) else {
            FidoLogger.debug("<MakeCredentialSession> insufficient capability (alg), stop session")
            self.stop(by: .unsupported)
            return
        }
  
        if requireUserVerification && !self.setting.allowUserVerification {
            FidoLogger.debug("<MakeCredentialSession> insufficient capability (user verification), stop session")
            self.stop(by: FidoError.constraint)
            return
        }
        
        do{
            try await BiometricVerification.verifyUser(message: "Necesitamos verificar tu identidad", context: self.context)
            let credentialId = self.createNewCredentialId()
            
            let credSource = PublicKeyCredentialSource(
                id:         credentialId,
                rpId:       rpEntity.id!,
                userHandle: userEntity.id,
                signCount:  0,
                alg:        keySupport.selectedAlg.rawValue
            )
            self.credentialStore.setContext(context: self.context)
            try self.credentialStore.deleteAllCredentialSources(
                rpId:       credSource.rpId,
                userHandle: credSource.userHandle
            )
            
            keySupport.deleteAllKeyPairs()
            guard let publicKeyCOSE = keySupport.createKeyPair() else {
                self.stop(by: .unknown)
                return
            }
            
            if !self.credentialStore.saveCredentialSource(credSource) {
                FidoLogger.debug("<MakeCredentialSession> failed to save credential source, stop session")
                self.stop(by: .unknown)
                return
            }
            
            let extensions = SimpleOrderedDictionary<String>()
            
            let attestedCredData = AttestedCredentialData(
                aaguid:              UUIDHelper.zeroBytes,
                credentialId:        credentialId,
                credentialPublicKey: publicKeyCOSE
            )
            
            let authenticatorData = AuthenticatorData(
                rpIdHash:               [UInt8](SHA256.hash(data: Data(rpEntity.id!.utf8))),
                userPresent:            (requireUserPresence || requireUserVerification),
                userVerified:           requireUserVerification,
                signCount:              0,
                attestedCredentialData: attestedCredData,
                extensions:             extensions
            )
            
            guard let attestation =
                    SelfAttestation.create(
                        authData:       authenticatorData,
                        clientDataHash: hash,
                        alg:            keySupport.selectedAlg,
                        keyLabel:       credSource.keyLabel,
                        context:        self.context
                    ) else {
                FidoLogger.debug("<MakeCredentialSession> failed to build attestation object")
                self.stop(by: .unknown)
                return
            }
            
            self.completed()
            self.delegate?.authenticatorSessionDidMakeCredential(
                session:     self,
                attestation: attestation
            )
            
        }catch {
            if let authError = error as? FidoError {
                self.stop(by: authError)
            }else{
                self.stop(by: .unknown)
            }
        }
    }

    private func lookupCredentialSource(rpId: String, credentialId: [UInt8]) -> Optional<PublicKeyCredentialSource> {
        FidoLogger.debug("<MakeCredentialSession> lookupCredentialSource")
        return self.credentialStore.lookupCredentialSource(
            rpId:         rpId,
            credentialId: credentialId
        )
    }
    
}

