//
//  Fido2Auth.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication
import CryptoKit

public enum ClientOperationType {
    case get
    case create
}

public protocol ClientOperationDelegate {
    func operationDidFinish(opType: ClientOperationType, opId: String)
}

@available(iOS 13.0, *)
public class Fido2Auth: ClientOperationDelegate {
    
    public typealias CreateResponse = PublicKeyCredential<AuthenticatorAttestationResponse>
    public typealias GetResponse = PublicKeyCredential<AuthenticatorAssertionResponse>
    
    public let origin: String
    
    public var defaultTimeout: UInt64 = 60
    public var minTimeout: UInt64 = 15
    public var maxTimeout: UInt64 = 120
    
    private let authenticator: Authenticator
    
    private var getOperations = [String: ClientGetOperation]()
    private var createOperations = [String: ClientCreateOperation]()
    
    public init(
        origin:        String,
        authenticator: Authenticator
    ) {
        self.origin        = origin
        self.authenticator = authenticator
    }
    
    public func create(_ options: PublicKeyCredentialCreationOptions, context: LAContext? = nil) async throws -> CreateResponse {
        FidoLogger.debug("<WebAuthnClient> create")
        let op = self.newCreateOperation(options, context: context)
        op.delegate = self
        self.createOperations[op.id] = op
        return try await op.start()
    }
    
    public func get(_ options: PublicKeyCredentialRequestOptions, context: LAContext? = nil) async throws -> GetResponse {
        FidoLogger.debug("<WebAuthnClient> get")
        let op = self.newGetOperation(options, context: context)
        op.delegate = self
        self.getOperations[op.id] = op
        return try await op.start()
    }
    
    public func cancel() {
        FidoLogger.debug("<WebAuthnClient> cancel")
        self.getOperations.forEach { $0.value.cancel() }
        self.createOperations.forEach { $0.value.cancel() }
    }
    
    public func newCreateOperation(_ options: PublicKeyCredentialCreationOptions, context: LAContext?) -> ClientCreateOperation {
        
        FidoLogger.debug("<WebAuthnClient> newCreateOperation")
        
        let lifetimeTimer = self.adjustLifetimeTimer(options.timeout)
        let rpId = self.pickRelyingPartyID(options.rp.id)
        
        let (clientData, clientDataJSON, clientDataHash) = self.generateClientData(
            type:      .webAuthnCreate,
            challenge: Base64.encodeBase64URL(options.challenge)
        )
        
        let session = self.authenticator.newMakeCredentialSession(context: context)
        
        return ClientCreateOperation(
            options:        options,
            rpId:           rpId,
            session:        session,
            clientData:     clientData,
            clientDataJSON: clientDataJSON,
            clientDataHash: clientDataHash,
            lifetimeTimer:  lifetimeTimer
        )
        
    }
    
    public func newGetOperation(_ options: PublicKeyCredentialRequestOptions, context: LAContext?)
    -> ClientGetOperation {
        
        FidoLogger.debug("<WebAuthnClient> newGetOperation")
        
        let lifetimeTimer = self.adjustLifetimeTimer(options.timeout)
        let rpId = self.pickRelyingPartyID(options.rpId)
        
        let (clientData, clientDataJSON, clientDataHash) =
        self.generateClientData(
            type:      .webAuthnGet,
            challenge: Base64.encodeBase64URL(options.challenge)
        )
        
        let session = self.authenticator.newGetAssertionSession(context: context)
        
        return ClientGetOperation(
            options:        options,
            rpId:           rpId,
            session:        session,
            clientData:     clientData,
            clientDataJSON: clientDataJSON,
            clientDataHash: clientDataHash,
            lifetimeTimer:  lifetimeTimer
        )
    }
    
    public func operationDidFinish(opType: ClientOperationType, opId: String) {
        FidoLogger.debug("<WebAuthnClient> operationDidFinish")
        switch opType {
        case .get:
            self.getOperations.removeValue(forKey: opId)
        case .create:
            self.createOperations.removeValue(forKey: opId)
        }
    }
    
    private func adjustLifetimeTimer(_ timeout: UInt64?) -> UInt64 {
        FidoLogger.debug("<WebAuthnClient> adjustLifetimeTimer")
        if let t = timeout {
            if (t < self.minTimeout) {
                return self.minTimeout
            }
            if (t > self.maxTimeout) {
                return self.maxTimeout
            }
            return t
        } else {
            return self.defaultTimeout
        }
    }
    
    private func pickRelyingPartyID(_ rpId: String?) -> String {
        
        FidoLogger.debug("<WebAuthnClient> pickRelyingPartyID")
        
        if let _rpId = rpId {
            return _rpId
        } else {
            return self.origin
        }
    }
    
    private func generateClientData(
        type:      CollectedClientDataType,
        challenge: String
    ) -> (CollectedClientData, String, [UInt8]) {
        
        FidoLogger.debug("<WebAuthnClient> generateClientData")
        
        let clientData = CollectedClientData(
            type:         type,
            challenge:    challenge,
            origin:       self.origin,
            tokenBinding: nil
        )
        
        let jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .withoutEscapingSlashes
        let clientDataJSONData = try! jsonEncoder.encode(clientData)
        let clientDataJSON = String(data: clientDataJSONData, encoding: .utf8)!
        let clientDataHash = [UInt8](SHA256.hash(data: Data(clientDataJSON.utf8)))
        
        return (clientData, clientDataJSON, clientDataHash)
    }
    
}

