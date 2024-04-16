//
//  ContentView.swift
//  custom-fido-app
//
//  Created by Antonio Alanya on 1/04/24.
//

import SwiftUI
import JWTDecode
import LocalAuthentication

enum UIErr: Error {
    case unhandled
    case noPublicKey
    case noPrivateKey
}
struct SaveDetails: Identifiable {
    let name: String
    let error: String
    let id = UUID()
}

struct ContentView: View {
    @State private var isLoggedIn:Bool = false
    @State private var didError = false
    @State private var errorMessage = ""
    
    @State private var presenting = SaveDetails(name: "NAME", error: "ERROR")
    
    func decodebase64(value:String)->String?{
        let base64EncodedData = value.data(using: .utf8)!
        return String(data:Data(base64Encoded: base64EncodedData)!, encoding: .utf8)
    }
    
    func toBase64(value: String) -> String {
        return Data(value.utf8).base64EncodedString()
    }
    
    func step1()  async throws -> [String: Any] {
        let url = URL(string: "http://192.168.1.104:3000/api/auth/register")!
        var request = URLRequest(url: url)
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpMethod = "POST"
        let json: [String: Any] = ["username": "73047716"]
        let jsonData = try? JSONSerialization.data(withJSONObject: json)
        request.httpBody = jsonData
        let (data, _) = try await URLSession.shared.data(for: request)
        let responseJSON = try JSONSerialization.jsonObject(with: data, options: [])
        return responseJSON as! [String: Any]
    }
    
    func step2(userId:String) async throws -> [String: Any] {
        let url = URL(string: "http://192.168.1.104:3000/api/auth/create-register-challenge")!
        var request = URLRequest(url: url)
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpMethod = "POST"
        let json: [String: Any] = ["userId": userId]
        let jsonData = try? JSONSerialization.data(withJSONObject: json)
        request.httpBody = jsonData
        let (data, _) = try await URLSession.shared.data(for: request)
        let responseJSON = try JSONSerialization.jsonObject(with: data, options: [])
        return responseJSON as! [String: Any]
    }
    
    func step3(data: PublicKeyCredential<AuthenticatorAttestationResponse>, token: String) async throws -> [String: Any] {
        let url = URL(string: "http://192.168.1.104:3000/api/auth/confirm-register-challenge")!
        var request = URLRequest(url: url)
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpMethod = "POST"
        let json: [String: Any] = [
            "id": Base64.encodeBase64(data.rawId),
            "challengeToken": token,
            "rawId": Base64.encodeBase64(data.rawId),
            "response": [
                "attestationObject": Base64.encodeBase64URL(data.response.attestationObject),
                "clientDataJSON": Base64.encodeBase64URL(data.response.clientDataJSON.data(using: .utf8)!),
            ]
        ]
        let jsonData = try? JSONSerialization.data(withJSONObject: json)
        request.httpBody = jsonData
        let (data, _) = try await URLSession.shared.data(for: request)
        let responseJSON = try JSONSerialization.jsonObject(with: data, options: [])
        return responseJSON as! [String: Any]
    }
    
    func register() {
        FidoLogger.available = true
        Task {
            do {
                let respStep1 = try await step1()
                
                let defaults = UserDefaults.standard
                defaults.set(respStep1["userId"] as! String, forKey: "userId")
                
                let respStep2 = try await step2(userId: respStep1["userId"] as! String)
                let jwt = try decode(jwt: respStep2["challengeToken"] as! String )
                guard let base64UserId = jwt["base64UserId"].string else {
                    throw UIErr.unhandled
                }
                guard let challenge = jwt["challenge"].string else {
                    throw UIErr.unhandled
                }
                guard let userId = decodebase64(value: base64UserId) else {
                    throw UIErr.unhandled
                }
                guard let name = decodebase64(value: (respStep2["user"] as! [String: Any])["name"] as! String)  else{
                    throw UIErr.unhandled
                }
                guard let displayName = decodebase64(value:(respStep2["user"] as! [String: Any])["displayName"] as! String) else{
                    throw UIErr.unhandled
                }
                guard let rpid = ((respStep2["rp"] as! [String: Any])["id"] as? String) else{
                    throw UIErr.unhandled
                }
                
                if let bundleIdentifier = Bundle.main.bundleIdentifier {
                    print("Bundle Identifier: \(bundleIdentifier)")
                } else {
                    print("Unable to retrieve bundle identifier.")
                }
                
                
                let authContext = LAContext()
                let authenticator = AuthenticatorProvider(context: authContext)
                let webAuthnClient = Fido2Auth(
                    origin:        "https://joseaki.github.io",
                    authenticator: authenticator
                )
                
                var options = PublicKeyCredentialCreationOptions()
                print("Initial Challenge " + challenge)
                options.challenge = [UInt8](Data(base64Encoded: challenge)!)
                options.user.id = [UInt8](userId.utf8)
                options.user.name = name
                options.user.displayName = displayName
                
                options.rp.id = rpid
                options.rp.name = "iO"
                
                options.attestation = AttestationConveyancePreference.none
                options.addPubKeyCredParam(alg: .es256)
                options.authenticatorSelection = AuthenticatorSelectionCriteria(
                    requireResidentKey: true,
                    userVerification: UserVerificationRequirement.required
                )
                
                do{
                    let credential = try await webAuthnClient.create(options, context: authContext)
                    print("==========================================")
                    print("credentialId: " + credential.id)
                    print("rawId: " + Base64.encodeBase64URL(credential.rawId))
                    print("attestationObject: " + Base64.encodeBase64(credential.response.attestationObject))
                    print("clientDataJSON: " + Base64.encodeBase64URL(credential.response.clientDataJSON.data(using: .utf8)!))
                    let _ = try await step3(data: credential, token:  respStep2["challengeToken"] as! String)
                } catch let error {
                    print("Error \(error)")
                    FidoLogger.debug("FIDO GENERAL ERROR")
                    presenting = SaveDetails(name: "NAME", error: "\(error)")
                    didError = true
                }
                
            } catch {
                print("Failed to Send POST Request \(error)")
            }
        }
        
    }
    
    func loginStep1() async throws -> [String: Any]{
        let url = URL(string: "http://192.168.1.104:3000/api/auth/create-auth-challenge")!
        var request = URLRequest(url: url)
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpMethod = "POST"
        
        let defaults = UserDefaults.standard
        let userId = defaults.string(forKey: "userId")
        
        let json = ["userId": userId]
        let jsonData = try? JSONSerialization.data(withJSONObject: json)
        request.httpBody = jsonData
        let (data, _) = try await URLSession.shared.data(for: request)
        let responseJSON = try JSONSerialization.jsonObject(with: data, options: [])
        return responseJSON as! [String: Any]
    }
    
    func loginStep2(data: PublicKeyCredential<AuthenticatorAssertionResponse>, token:String) async throws{
        
        let url = URL(string: "http://192.168.1.104:3000/api/auth/confirm-auth-challenge")!
        var request = URLRequest(url: url)
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpMethod = "POST"
        let json: [String: Any] = [
            "challengeToken": token,
            "id": Base64.encodeBase64(data.rawId),
            "rawId": Base64.encodeBase64(data.rawId),
            "response": [
                "authenticatorData": Base64.encodeBase64(data.response.authenticatorData),
                "userHandle": Base64.encodeBase64URL(data.response.userHandle!),
                "clientDataJSON": Base64.encodeBase64URL(data.response.clientDataJSON.data(using: .utf8)!),
                "signature": Base64.encodeBase64URL(data.response.signature)
            ]
        ]
        let jsonData = try? JSONSerialization.data(withJSONObject: json)
        request.httpBody = jsonData
        let (_, _) = try await URLSession.shared.data(for: request)
        
    }
    
    func login() {
        isLoggedIn = false
        FidoLogger.available = true
        
        Task{
            do{
                let respStep1 = try await loginStep1()
                let jwt = try decode(jwt: respStep1["challengeToken"] as! String )
                guard jwt["base64UserId"].string != nil else {
                    throw UIErr.unhandled
                }
                guard let challenge = jwt["challenge"].string else {
                    throw UIErr.unhandled
                }
                print("Challenge login: "+challenge)
                
                var options = PublicKeyCredentialRequestOptions()
                options.challenge = [UInt8](Data(base64Encoded: challenge)!)
                options.rpId = (respStep1["rpId"] as! String)
                options.userVerification = UserVerificationRequirement.required
                
                let authContext = LAContext()
                let authenticator = AuthenticatorProvider(context: authContext)
                let webAuthnClient = Fido2Auth(
                    origin:        "https://joseaki.github.io",
                    authenticator: authenticator
                )
                let assertion = try await webAuthnClient.get(options, context: authContext)
                
                print("==========================================")
                print("credentialId: " + assertion.id)
                print("rawId: " + Base64.encodeBase64URL(assertion.rawId))
                print("authenticatorData: " + Base64.encodeBase64URL(assertion.response.authenticatorData))
                print("signature: " + Base64.encodeBase64URL(assertion.response.signature))
                print("userHandle: " + Base64.encodeBase64URL(assertion.response.userHandle!))
                print("clientDataJSON: " + Base64.encodeBase64URL(assertion.response.clientDataJSON.data(using: .utf8)!))
                print("==========================================")
                
                try await loginStep2(data: assertion, token:respStep1["challengeToken"] as! String )
                isLoggedIn = true
            }catch let error{
                print("Error"+error.localizedDescription)
                FidoLogger.debug("FIDO GENERAL ERROR \(error)")
                presenting = SaveDetails(name: "NAME", error: "\(error)")
                didError = true
            }
        }
    }
    
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Hello, world!")
            Button(action: register) {
                Text("Register")
            }.alert(
                "Error",
                isPresented: $didError,
                presenting: presenting
            ) { details in
//                Button(role: .destructive) {
//                    // Handle the deletion.
//                } label: {
//                    Text("Delete")
//                }
                
            } message: { details in
                Text(details.error)
            }
            Button(action: login) {
                Text("Sign In")
            }.alert(
                "Error",
                isPresented: $didError,
                presenting: presenting
            ) { details in
//                Button(role: .destructive) {
//                    // Handle the deletion.
//                } label: {
//                    Text("Delete")
//                }
                
            } message: { details in
                Text(details.error)
            }
            Group {
                if isLoggedIn {
                    Text("Sesion iniciada!!")
                }
            }
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
