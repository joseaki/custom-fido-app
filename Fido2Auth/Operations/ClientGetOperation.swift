//
//  ClientGetOperation.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation


@available(iOS 13.0, *)
public class ClientGetOperation: AuthenticatorGetAssertionSessionDelegate {
    
    public let id = UUID().uuidString
    public let type = ClientOperationType.get
    
    public var delegate: ClientOperationDelegate?

    private let options:        PublicKeyCredentialRequestOptions
    private let rpId:           String
    private let clientData:     CollectedClientData
    private let clientDataJSON: String
    private let clientDataHash: [UInt8]
    private let lifetimeTimer:  UInt64

    private var savedCredentialId: [UInt8]?

    private var session: AuthenticatorGetAssertionSession
    private var resolver: CheckedContinuation<Fido2Auth.GetResponse, Error>?
    private var stopped: Bool = false

    private var timer: DispatchSource?

    internal init(
        options:        PublicKeyCredentialRequestOptions,
        rpId:           String,
        session:        AuthenticatorGetAssertionSession,
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

    public func start() async throws -> Fido2Auth.GetResponse {
      FidoLogger.debug("<GetOperation> start")
      return try await withCheckedThrowingContinuation { resolver in
        DispatchQueue.global().async {
            if self.stopped {
                FidoLogger.debug("<GetOperation> already stopped")
                DispatchQueue.main.async {
                  resolver.resume(throwing: FidoError.badOperation)
                }
                self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
                return
            }
            
            let transports: [AuthenticatorTransport] =
                self.options.allowCredentials.flatMap { $0.transports }
            
            if !transports.isEmpty
                && !transports.contains(self.session.transport) {
                FidoLogger.debug("<GetOperation> transport mismatch")
                DispatchQueue.main.async {
                    resolver.resume(throwing: FidoError.notAllowed)
                }
                self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
                return
            }
            
            if self.resolver != nil {
                FidoLogger.debug("<GetOperation> already started")
                DispatchQueue.main.async {
                    resolver.resume(throwing: FidoError.badOperation)
                }
                self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
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
        FidoLogger.debug("<GetOperation> cancel")
        if self.resolver != nil && !self.stopped {
            DispatchQueue.global().async {
                if self.session.transport == .internal_ {
                    FidoLogger.debug("<GetOperation> session is 'internal', send 'cancel' to session")
                    self.session.cancel(reason: reason)
                } else {
                    FidoLogger.debug("<GetOperation> session is not 'internal', close operation")
                    self.stop(by: reason)
                }
            }
        }
    }
    
    private func completed() {
        FidoLogger.debug("<GetOperation> completed")
        if self.resolver == nil {
            FidoLogger.debug("<GetOperation> not started")
            return
        }
        if self.stopped {
            FidoLogger.debug("<GetOperation> already stopped")
            return
        }
        self.stopped = true
        self.stopLifetimeTimer()
        self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
    }

    private func stopInternal(reason: FidoError) {
        FidoLogger.debug("<GetOperation> stop")
        if self.resolver == nil {
            FidoLogger.debug("<GetOperation> not started")
            return
        }
        if self.stopped {
            FidoLogger.debug("<GetOperation> already stopped")
            return
        }
        self.stopped = true
        self.stopLifetimeTimer()
        self.session.cancel(reason: reason)
        self.delegate?.operationDidFinish(opType: self.type, opId: self.id)
    }
    
    private func startLifetimeTimer() {
        FidoLogger.debug("<GetOperation> startLifetimeTimer \(self.lifetimeTimer) sec")
        if self.timer != nil {
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

    private func stop(by error: FidoError) {
        FidoLogger.debug("<GetOperation> stop by \(error)")
        self.stopInternal(reason: error)
        self.dispatchError(error)
    }

    private func dispatchError(_ error: FidoError) {
        FidoLogger.debug("<GetOperation> dispatchError")
        DispatchQueue.main.async {
            if let resolver = self.resolver {
              resolver.resume(throwing: error)
                self.resolver = nil
            }
        }
    }

    private func stopLifetimeTimer() {
        FidoLogger.debug("<GetOperation> stopLifetimeTimer")
        self.timer?.cancel()
        self.timer = nil
    }

    @objc func lifetimeTimerTimeout() {
        FidoLogger.debug("<GetOperation> timeout")
        self.stopLifetimeTimer()
        self.cancel(reason: .timeout)
    }

    private func judgeUserVerificationExecution(_ session: AuthenticatorGetAssertionSession) -> Bool {
        FidoLogger.debug("<GetOperation> judgeUserVerificationExecution")
        switch self.options.userVerification {
        case .required:
            return true
        case .preferred:
            return session.canPerformUserVerification()
        case .discouraged:
            return false
        }
    }

    public func authenticatorSessionDidBecomeAvailable(session: AuthenticatorGetAssertionSession) {

        FidoLogger.debug("<GetOperation> authenticator become available")
        
        if self.stopped {
            FidoLogger.debug("<GetOperation> already stopped")
            return
        }

        if self.options.userVerification == .required
            && !session.canPerformUserVerification() {
            FidoLogger.debug("<GetOperation> user-verification is required, but this authenticator doesn't support")
            self.stop(by: .unsupported)
            return
        }

        let userVerification = self.judgeUserVerificationExecution(session)

        let userPresence = !userVerification

        if self.options.allowCredentials.isEmpty {

            session.getAssertion(
                rpId:                          self.rpId,
                hash:                          self.clientDataHash,
                allowCredentialDescriptorList: self.options.allowCredentials,
                requireUserPresence:           userPresence,
                requireUserVerification:       userVerification
            )

        } else {

            let allowCredentialDescriptorList = self.options.allowCredentials.filter {
                $0.transports.contains(session.transport)
            }

            if (allowCredentialDescriptorList.isEmpty) {
                FidoLogger.debug("<GetOperation> no matched credential on this authenticator")
                self.stop(by: .notAllowed)
                return
            }

            if allowCredentialDescriptorList.count == 1 {
                self.savedCredentialId = allowCredentialDescriptorList[0].id
            }

            session.getAssertion(
                rpId:                          self.rpId,
                hash:                          self.clientDataHash,
                allowCredentialDescriptorList: allowCredentialDescriptorList,
                requireUserPresence:           userPresence,
                requireUserVerification:       userVerification
            )

        }
    }

    public func authenticatorSessionDidDiscoverCredential(
        session:   AuthenticatorGetAssertionSession,
        assertion: AuthenticatorAssertionResult
    ) {
        
        FidoLogger.debug("<GetOperation> authenticator discovered credential")
        
        var credentialId: [UInt8]
        if let savedId = self.savedCredentialId {
            FidoLogger.debug("<GetOperation> use saved credentialId")
           credentialId = savedId
        } else {
            FidoLogger.debug("<GetOperation> use credentialId from authenticator")
            guard let resultId = assertion.credentailId else {
                FidoLogger.debug("<GetOperation> credentialId not found")
                self.dispatchError(.unknown)
                return
            }
            credentialId = resultId
        }

        let cred = PublicKeyCredential<AuthenticatorAssertionResponse>(
            rawId:    credentialId,
            id:       Base64.encodeBase64URL(credentialId),
            response: AuthenticatorAssertionResponse(
                clientDataJSON:    self.clientDataJSON,
                authenticatorData: assertion.authenticatorData,
                signature:         assertion.signature,
                userHandle:        assertion.userHandle
            )
        )

        self.completed()
        
        DispatchQueue.main.async {
            if let resolver = self.resolver {
                resolver.resume(returning: cred)
                self.resolver = nil
            }
        }
    }

    public func authenticatorSessionDidBecomeUnavailable(session: AuthenticatorGetAssertionSession) {
        FidoLogger.debug("<GetOperation> authenticator become unavailable")
        self.stop(by: .notAllowed)
    }

    public func authenticatorSessionDidStopOperation(
        session: AuthenticatorGetAssertionSession,
        reason:  FidoError
    ) {
        FidoLogger.debug("<GetOperation> authenticator stopped operation")
        self.stop(by: reason)
    }

}

