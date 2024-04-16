//
//  BiometricVerification.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication

@available(iOS 13.0, *)
class BiometricVerification {
    public static func verifyUser(message: String, context: LAContext) async throws {
        FidoLogger.debug("<BiometricVerification> verifyUser")
        
        var error: NSError?
        context.localizedFallbackTitle = "";
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            let reason = error?.localizedDescription ?? ""
            FidoLogger.debug("<BiometricVerification> Can't evaluate policy 1: \(reason)")
            if let authError = error as? LAError {
                switch authError.code {
                case LAError.Code.userCancel,LAError.Code.appCancel,LAError.Code.systemCancel:
                    throw FidoError.cancelled
                case LAError.Code.biometryLockout, LAError.Code.biometryNotEnrolled, LAError.Code.biometryNotAvailable:
                    throw FidoError.noBiometry
                default:
                    throw FidoError.unknown
                }
            }
            throw FidoError.unknown
        }
        
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: message)
        } catch let error {
            FidoLogger.debug("<BiometricVerification> Can't evaluate policy 2: \(error.localizedDescription) \(error._code)")
            if let authError = error as? LAError {
                switch authError.code {
                case LAError.Code.userCancel,LAError.Code.appCancel,LAError.Code.systemCancel:
                    throw FidoError.cancelled
                case LAError.Code.biometryLockout, LAError.Code.biometryNotEnrolled, LAError.Code.biometryNotAvailable:
                    throw FidoError.noBiometry
                case LAError.Code.authenticationFailed:
                    throw FidoError.notAllowed
                default:
                    throw FidoError.unknown
                }
            }
            throw error
        }
    }
}
