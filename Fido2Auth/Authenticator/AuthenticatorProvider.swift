//
//  AuthenticatorProvider.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication

public struct InternalAuthenticatorSetting {
    public let attachment: AuthenticatorAttachment = .platform
    public let transport: AuthenticatorTransport = .internal_
    public var counterStep: UInt32
    public var allowUserVerification: Bool
    
    public init(
        counterStep:           UInt32 = 1,
        allowUserVerification: Bool = true
    ) {
        self.counterStep           = counterStep
        self.allowUserVerification = allowUserVerification
    }
}

@available(iOS 13.0, *)
public class AuthenticatorProvider : Authenticator {
   
    
    public var setting = InternalAuthenticatorSetting()
    
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
    
    public var counterStep: UInt32 {
        get {
            return self.setting.counterStep
        }
        set(value) {
            self.setting.counterStep = value
        }
    }
    
    public var allowUserVerification: Bool {
        get {
            return self.setting.allowUserVerification
        }
        set(value) {
            self.setting.allowUserVerification = value
        }
    }
    
    public var allowResidentKey: Bool {
        get {
            return true
        }
    }

    private let credentialStore: CredentialStore

    private let keySupportChooser = KeySupportChooser()
    
    public convenience init(context: LAContext) {
        let store = KeychainCredentialStore(context:context )
        self.init(
            credentialStore: store
        )
    }

    public init(
        credentialStore: CredentialStore
    ) {
        self.credentialStore = credentialStore
    }

    public func newMakeCredentialSession(context: LAContext?) -> AuthenticatorMakeCredentialSession {
        FidoLogger.debug("<InternalAuthenticator> newMakeCredentialSession")
        return AuthenticatorCreateCredentialsSession(
            setting:           self.setting,
            credentialStore:   self.credentialStore,
            keySupportChooser: self.keySupportChooser,
            context:           context
        )
    }
    
    public func newGetAssertionSession(context: LAContext?) -> AuthenticatorGetAssertionSession {
        FidoLogger.debug("<InternalAuthenticator> newGetAssertionSession")
        return AuthenticatorGetCredentialsAssertionSession(
            setting:           self.setting,
            credentialStore:   self.credentialStore,
            keySupportChooser: self.keySupportChooser,
            context:           context
        )
    }

}
