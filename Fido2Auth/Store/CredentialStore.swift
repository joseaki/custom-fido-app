//
//  CredentialStore.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation
import LocalAuthentication

public protocol CredentialStore {
    func setContext(context: LAContext) -> Void
    func lookupCredentialSource(rpId: String, credentialId: [UInt8]) -> Optional<PublicKeyCredentialSource>
    func saveCredentialSource(_ cred: PublicKeyCredentialSource) -> Bool
    func loadAllCredentialSources(rpId: String) throws -> [PublicKeyCredentialSource]
    func deleteCredentialSource(_ cred: PublicKeyCredentialSource) -> Bool
    func deleteAllCredentialSources(rpId: String, userHandle: [UInt8]) throws
}

public class KeychainCredentialStore : CredentialStore {
    var context:LAContext;
    init(context: LAContext = LAContext()) {
        self.context = context
        self.context.localizedReason = "Bonjour init"
    }
    
    public func setContext(context: LAContext) {
        self.context = context
        self.context.localizedReason = "Bonjour set"
    }
    
    public func loadAllCredentialSources(rpId: String) throws -> [PublicKeyCredentialSource] {
        FidoLogger.debug("<KeychainStore> loadAllCredentialSources")
        return try getAllKeychainKeys(service: rpId).compactMap {
            FidoLogger.debug("<KeychainStore> getting keychain data \($0)")
            if let result = try? getKeychainData($0, service: rpId) {
                let resultArray = [UInt8](result);
                return PublicKeyCredentialSource.fromCBOR(resultArray)
            } else {
                FidoLogger.debug("<KeychainStore> failed to load data for key:\($0)")
                return nil
            }
        }
    }
    
    public func deleteAllCredentialSources(rpId: String, userHandle: [UInt8]) throws {
        try self.loadAllCredentialSources(rpId: rpId, userHandle: userHandle).forEach {
            FidoLogger.debug("<KeychainStore> deleting \($0)")
            _ = self.deleteCredentialSource($0)
        }
    }
    
    public func loadAllCredentialSources(rpId: String, userHandle: [UInt8]) throws -> [PublicKeyCredentialSource] {
        FidoLogger.debug("<KeychainStore> loadAllCredentialSources with userHandle")
        return try self.loadAllCredentialSources(rpId: rpId).filter { _ in true }
    }
    
    public func lookupCredentialSource(rpId: String, credentialId: [UInt8]) -> Optional<PublicKeyCredentialSource> {
        FidoLogger.debug("<KeychainStore> lookupCredentialSource")
        let handle = toHexString(credentialId)
        
        if let result = try? getKeychainData(handle, service: rpId) {
            let resultArray = [UInt8](result);
            return PublicKeyCredentialSource.fromCBOR(resultArray)
        } else {
            FidoLogger.debug("<KeychainStore> failed to load data for key:\(handle)")
            return nil
        }
    }
    
    public func deleteCredentialSource(_ cred: PublicKeyCredentialSource) -> Bool {
        FidoLogger.debug("<KeychainStore> deleteCredentialSource")
        let handle = toHexString(cred.id)
        
        do {
            try removeKeychainData(handle, service: cred.rpId)
            return true
        } catch let error {
            FidoLogger.debug("<KeychainStore> failed to delete credential-source: \(error)")
            return false
        }
        
    }
    
    public func saveCredentialSource(_ cred: PublicKeyCredentialSource) -> Bool {
        FidoLogger.debug("<KeychainStore> saveCredentialSource \(Base64.encodeBase64(cred.id))")
        let handle = toHexString(cred.id)
        
        if let bytes = cred.toCBOR() {
            do {
                try upsertKeychainData(handle, service: cred.rpId, data: Data(_: bytes))
                return true
            } catch let error {
                FidoLogger.debug("<KeychainStore> failed to save credential-source: \(error)")
                return false
            }
        } else {
            return false
        }
    }
    // ======================= PRIVATE FUNCTIONS =====================================
    
    private func getKeychainData(_ key: String, service: String) throws -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecUseAuthenticationContext as String: self.context,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound
        else {
            throw KeychainError.noItemInKeychain
        }
        
        guard let existingItem = item as? [String : Any],
              let data = existingItem[kSecValueData as String] as? Data
        else {
            throw KeychainError.unexpectedItemData
        }
        
        return data
    }
    
    private func removeKeychainData(_ key: String, service: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound
        else {
            throw KeychainError.noItemInKeychain
        }
    }
    
    private func upsertKeychainData(_ key: String, service: String, data: Data) throws {
        do{
            let searchQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                              kSecAttrService as String: service,
                                              kSecAttrAccount as String: key,
                                              kSecUseAuthenticationContext as String: self.context]
            
            
            
            var item: CFTypeRef?
            var status = SecItemCopyMatching(searchQuery as CFDictionary, &item)
            switch status {
            case errSecSuccess, errSecInteractionNotAllowed:
                if status == errSecInteractionNotAllowed {
                    try removeKeychainData(key, service: service)
                    try upsertKeychainData(key, service: service, data: data)
                } else {
                    let attributes: [String: Any] = [kSecValueData as String: data]
                    status = SecItemUpdate(searchQuery as CFDictionary, attributes as CFDictionary)
                    if status != errSecSuccess {
                        FidoLogger.debug("<KeychainStore> failed to update keychain \(status)")
                        throw KeychainError.unableToUpdateKeychainValue
                    }
                }
            case errSecItemNotFound:
                try createKeychainData(key, service: service, data: data)
            default:
                FidoLogger.debug("<KeychainStore> failed to add to keychain")
                throw KeychainError.unableToAddKeychainValue
            }
            
            
        }catch let error{
            throw error
        }
        
        
    }
    
    private func createKeychainData(_ key: String, service: String, data: Data) throws {
        let accessControlError:UnsafeMutablePointer<Unmanaged<CFError>?>? = nil;
        let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                     SecAccessControlCreateFlags.biometryCurrentSet,
                                                     accessControlError)
        
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key,
                                    kSecAttrAccessControl as String: access as Any,
                                    kSecValueData as String: data]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess
        else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    private func getAllKeychainItems(service: String) throws -> [[String: Any]] {
        var result: AnyObject?
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecMatchLimit as String: kSecMatchLimitAll,
                                    kSecUseAuthenticationContext as String: self.context,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true
        ]
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        print("STATUS GET ITEMS \(status)")
        switch status {
            case errSecSuccess:
                if let items = result as? [[String: Any]] {
                    return items
                }
            case errSecItemNotFound:
                return []
            case errSecAuthFailed:
                throw FidoError.notAllowed
            default: ()
        }
        
        return []
    }
    
    private func getAllKeychainKeys(service: String) throws -> [String]  {
        let items: [[String: Any]] = try self.getAllKeychainItems(service: service)
        let allItems = items.map{ attributes -> [String: Any] in
            var item = [String: Any]()
            if let key = attributes[kSecAttrAccount as String] as? String {
                item["key"] = key
            }
            return item
        }
        let filter: ([String: Any]) -> String? = { $0["key"] as? String }
        return allItems.compactMap(filter)
    }
}

