//
//  KeyPair.swift
//  matrix
//
//  Created by Antonio Alanya on 31/03/24.
//

import Foundation
import LocalAuthentication

enum KeyPairError: Error {
    case unhandled
    case noPublicKey
    case noPrivateKey
}

enum CertificateGenerationError: Error {
    case keyPairGenerationFailed
    case certificateCreationFailed
    case gettingPublicKeyFailed
    case gettingPrivateKeyFailed
    case keyNotFound
}

class KeyPair{
    let privateKeyLabel = "pe.io/private"
    let publicKeyLabel = "pe.io/public"
    var publicKey: SecKey?
    var privateKey: SecKey?
    var context:LAContext = LAContext();
    
    public func setContext(context: LAContext) {
        self.context = context
    }
    
    public func generateAsymetricKeyPair() throws -> (private: SecKey, public: PublicKeyData)  {
        FidoLogger.debug("<KeyPair> generating private key")
        
        let accessControlError:UnsafeMutablePointer<Unmanaged<CFError>?>? = nil;
        let privateAccess = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                            [SecAccessControlCreateFlags.biometryCurrentSet, .and, SecAccessControlCreateFlags.privateKeyUsage],
                                                            accessControlError)
        let publicAccess = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           [],
                                                           nil
        )
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String:[
                kSecAttrLabel as String: self.privateKeyLabel,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: privateAccess as Any
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrLabel as String: self.publicKeyLabel,
                kSecAttrAccessControl as String: publicAccess as Any
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else{
            throw KeyPairError.noPublicKey
        }
        self.publicKey = publicKey
        self.privateKey = privateKey
        
        var errorRawPublicKey:Unmanaged<CFError>?
        guard let rawPublicKey = SecKeyCopyExternalRepresentation(publicKey, &errorRawPublicKey) else {
            throw KeyPairError.noPublicKey
        }
      
        return (private: privateKey, public: PublicKeyData(rawPublicKey as Data))
    }
    
    
    public func deleteKeychainItem() {
        
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                    kSecAttrLabel as String: self.privateKeyLabel,
                                    kSecReturnRef as String: true
        ]
        
        SecItemDelete(query as CFDictionary)
        
    }
    
    private func searchPrivateKey() throws -> SecKey {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                    kSecAttrLabel as String: self.privateKeyLabel,
                                    kSecReturnRef as String: true,
                                    kSecUseAuthenticationContext as String: self.context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        print("searchPrivateKey \(status)")
        guard status == errSecSuccess else {
            throw CertificateGenerationError.keyNotFound
        }
        let key = item as! SecKey
        return key
    }
    
    public func getPrivateKey() throws -> SecKey {
        do{
            FidoLogger.debug("<KeyPair> get private key")
            let privateKey = try searchPrivateKey()
            self.privateKey = privateKey
            return privateKey
        }catch CertificateGenerationError.keyNotFound {
            do{
                let pair = try generateAsymetricKeyPair()
                return pair.private
            }catch {
                throw CertificateGenerationError.gettingPrivateKeyFailed
            }
        }catch{
            throw CertificateGenerationError.gettingPrivateKeyFailed
        }
    }
    
    public func getPublicKey() throws -> SecKey {
        do{
            let privateKey = try getPrivateKey()
            let publicKey = SecKeyCopyPublicKey(privateKey)
            let key = publicKey!
            return key
        }catch{
            throw CertificateGenerationError.gettingPublicKeyFailed
        }
    }
    
    public func sign(_ data: Data,  hash: SecKeyAlgorithm) throws -> Data {
        guard let privateKey = self.privateKey else{
            throw KeyPairError.noPrivateKey
        }
        
        var error: Unmanaged<CFError>?
        FidoLogger.debug("<KeyPair> signing data")
        guard let signature = SecKeyCreateSignature(privateKey,
                                                    hash,
                                                    data as CFData,
                                                    &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return signature as Data
    }
}
