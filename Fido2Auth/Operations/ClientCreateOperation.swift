//
//  ClientCreateOperation.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation

@available(iOS 13.0, *)
public class ClientCreateOperation: AuthenticatorMakeCredentialSessionDelegate {
  
  public let id = UUID().uuidString
  public let type = ClientOperationType.create
  
  public var delegate: ClientOperationDelegate?
  
  private let options:        PublicKeyCredentialCreationOptions
  private let rpId:           String
  private let clientData:     CollectedClientData
  private let clientDataJSON: String
  private let clientDataHash: [UInt8]
  private let lifetimeTimer:  UInt64
  
  private var session: AuthenticatorMakeCredentialSession
  
  private var resolver: CheckedContinuation<Fido2Auth.CreateResponse, Error>?
  private var stopped: Bool = false
  
  private var timer: DispatchSource?
  
  internal init(
    options:        PublicKeyCredentialCreationOptions,
    rpId:           String,
    session:        AuthenticatorMakeCredentialSession,
    clientData:     CollectedClientData,
    clientDataJSON: String,
    clientDataHash: [UInt8],
    lifetimeTimer:  UInt64
  ) {
    self.options        = options
    self.rpId           = rpId
    self.session        = session
    self.clientData     = clientData
    self.clientDataJSON = clientDataJSON
    self.clientDataHash = clientDataHash
    self.lifetimeTimer  = lifetimeTimer
  }
  
  public func start() async throws -> Fido2Auth.CreateResponse {
    FidoLogger.debug("<CreateOperation> start")
    return try await withCheckedThrowingContinuation { resolver in
      DispatchQueue.global().async {
        if self.stopped {
          FidoLogger.debug("<CreateOperation> already stopped")
          DispatchQueue.main.async {
            resolver.resume(throwing: FidoError.badOperation)
            self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
          }
          return
        }
        if self.resolver != nil {
          FidoLogger.debug("<CreateOperation> already started")
          DispatchQueue.main.async {
            resolver.resume(throwing: FidoError.badOperation)
            self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
          }
          return
        }
        self.resolver = resolver
        self.startLifetimeTimer()
        
        self.session.delegate = self
        self.session.start()
      }
    }
  }
  
  public func cancel(reason: FidoError = .cancelled) {
    FidoLogger.debug("<CreateOperation> cancel")
    if self.resolver != nil && !self.stopped {
      DispatchQueue.global().async {
        if self.session.transport == .internal_ {
          if reason == .timeout {
            self.session.cancel(reason: .timeout)
          } else {
            self.session.cancel(reason: .cancelled)
          }
        } else {
          self.stop(by: reason)
        }
      }
    }
  }
  
  private func completed() {
    FidoLogger.debug("<CreateOperation> completed")
    if self.resolver == nil {
      FidoLogger.debug("<CreateOperation> not started")
      return
    }
    if self.stopped {
      FidoLogger.debug("<CreateOperation> already stopped")
      return
    }
    self.stopped = true
    self.stopLifetimeTimer()
    self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
  }
  
  private func stopInternal(reason: FidoError) {
    FidoLogger.debug("<CreateOperation> stop")
    if self.resolver == nil {
      FidoLogger.debug("<CreateOperation> not started")
      return
    }
    if self.stopped {
      FidoLogger.debug("<CreateOperation> already stopped")
      return
    }
    self.stopped = true
    self.stopLifetimeTimer()
    self.session.cancel(reason: reason)
    self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
  }
  
  private func stop(by error: FidoError) {
    FidoLogger.debug("<CreateOperation> stop by \(error)")
    self.stopInternal(reason: error)
    self.dispatchError(error)
  }
  
  private func dispatchError(_ error: FidoError) {
    FidoLogger.debug("<CreateOperation> dispatchError")
    DispatchQueue.main.async {
      if let resolver = self.resolver {
        resolver.resume(throwing: error)
        self.resolver = nil
      }
    }
  }
  
  private func startLifetimeTimer() {
    FidoLogger.debug("<CreateOperation> startLifetimeTimer: \(self.lifetimeTimer) sec")
    if self.timer != nil {
      FidoLogger.debug("<CreateOperation> timer already started")
      return
    }
    if let timer = DispatchSource.makeTimerSource() as? DispatchSource {
      timer.schedule(deadline: .now() + TimeInterval(self.lifetimeTimer))
      timer.setEventHandler(handler: {
        [weak self] in
        self?.lifetimeTimerTimeout()
      })
      timer.resume()
      self.timer = timer
    }
  }
  
  private func stopLifetimeTimer() {
    FidoLogger.debug("<CreateOperation> stopLifetimeTimer")
    self.timer?.cancel()
    self.timer = nil
  }
  
  @objc func lifetimeTimerTimeout() {
    FidoLogger.debug("<CreateOperation> timeout")
    self.stopLifetimeTimer()
    self.cancel(reason: .timeout)
  }
  
  private func judgeUserVerificationExecution(_ session: AuthenticatorMakeCredentialSession) -> Bool {
    FidoLogger.debug("<CreateOperation> judgeUserVerificationExecution")
    let userVerificationRequest =
    self.options.authenticatorSelection?.userVerification ?? .discouraged
    switch userVerificationRequest {
    case .required:
      return true
    case .preferred:
      return session.canPerformUserVerification()
    case .discouraged:
      return false
    }
  }
  
  public func authenticatorSessionDidBecomeAvailable(session: AuthenticatorMakeCredentialSession) async {
    
    FidoLogger.debug("<CreateOperation> authenticator become available")
    
    if self.stopped {
      FidoLogger.debug("<CreateOperation> already stopped")
      return
    }
    
    if let selection = self.options.authenticatorSelection {
      
      if let attachment = selection.authenticatorAttachment {
        if attachment != session.attachment {
          FidoLogger.debug("<CreateOperation> authenticator's attachment doesn't match to RP's request")
          self.stop(by: .unsupported)
          return
        }
      }
      
      if selection.requireResidentKey
          && !session.canStoreResidentKey() {
        FidoLogger.debug("<CreateOperation> This authenticator can't store resident-key")
        self.stop(by: .unsupported)
        return
      }
      
      if selection.userVerification == .required
          && !session.canPerformUserVerification() {
        FidoLogger.debug("<CreateOperation> This authenticator can't perform user verification")
        self.stop(by: .unsupported)
        return
      }
    }
    
    let userVerification =
    self.judgeUserVerificationExecution(session)
    
    let userPresence = !userVerification
    
    let excludeCredentialDescriptorList =
    self.options.excludeCredentials.filter {descriptor in
      if descriptor.transports.contains(session.transport) {
        return false
      } else {
        return true
      }
    }
    
    let requireResidentKey =
    options.authenticatorSelection?.requireResidentKey ?? false
    
    let rpEntity = PublicKeyCredentialRpEntity(
      id:   self.rpId,
      name: options.rp.name,
      icon: options.rp.icon
    )
    
    await session.makeCredential(
      hash:                            self.clientDataHash,
      rpEntity:                        rpEntity,
      userEntity:                      options.user,
      requireResidentKey:              requireResidentKey,
      requireUserPresence:             userPresence,
      requireUserVerification:         userVerification,
      credTypesAndPubKeyAlgs:          options.pubKeyCredParams,
      excludeCredentialDescriptorList: excludeCredentialDescriptorList
    )
  }
  
  public func authenticatorSessionDidBecomeUnavailable(session: AuthenticatorMakeCredentialSession) {
    FidoLogger.debug("<CreateOperation> authenticator become unavailable")
    self.stop(by: .notAllowed)
  }
  
  public func authenticatorSessionDidMakeCredential(
    session:     AuthenticatorMakeCredentialSession,
    attestation: AttestationObject
  ) {
    FidoLogger.debug("<CreateOperation> authenticator made credential")
    
    guard let attestedCred = attestation.authData.attestedCredentialData else {
      FidoLogger.debug("<CreateOperation> attested credential data not found")
      self.dispatchError(.unknown)
      return
    }
    
    let credentialId = attestedCred.credentialId
      let credIDString = Base64.encodeBase64(credentialId)
      print("credIDString: " + credIDString)
    var atts = attestation
    
    var attestationObject: [UInt8]! = nil
    if self.options.attestation == .none && !attestation.isSelfAttestation() {
      FidoLogger.debug("<CreateOperation> attestation conveyance request is 'none', but this is not a self-attestation.")
      atts = attestation.toNone()
      guard let bytes = atts.toBytes() else {
        FidoLogger.debug("<CreateOperation> failed to build attestation-object")
        self.dispatchError(.unknown)
        return
      }
      attestationObject = bytes
      
      FidoLogger.debug("<CreateOperation> replace AAGUID with zero")
      let guidPos = 37 // ( rpIdHash(32), flag(1), signCount(4) )
      (guidPos..<(guidPos+16)).forEach { attestationObject[$0] = 0x00 }
    } else {
      guard let bytes = atts.toBytes() else {
        FidoLogger.debug("<CreateOperation> failed to build attestation-object")
        self.dispatchError(.unknown)
        return
      }
      attestationObject = bytes
    }
    
    let response =
    AuthenticatorAttestationResponse(
      clientDataJSON:    self.clientDataJSON,
      attestationObject: attestationObject
    )

    let cred = PublicKeyCredential<AuthenticatorAttestationResponse>(
      rawId:    credentialId,
      id:       Base64.encodeBase64URL(credentialId),
      response: response
    )
    
    self.completed()
    
    DispatchQueue.main.async {
      if let resolver = self.resolver {
        resolver.resume(returning: cred)
        self.resolver = nil
      }
    }
  }
  
  public func authenticatorSessionDidStopOperation(
    session: AuthenticatorMakeCredentialSession,
    reason:  FidoError
  ) {
    FidoLogger.debug("<CreateOperation> authenticator stopped operation")
    self.stop(by: reason)
  }
}
