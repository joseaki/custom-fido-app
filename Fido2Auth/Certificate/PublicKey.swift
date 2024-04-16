//
//  PublicKey.swift
//  custom-fido-app
//
//  Created by Antonio Alanya on 9/04/24.
//

import Foundation
public final class PublicKeyData {
    
    // As received from Security framework
    public let raw: Data
    
    // The open ssl compatible DER format X.509
    //
    // We take the raw key and prepend an ASN.1 headers to it. The end result is an
    // ASN.1 SubjectPublicKeyInfo structure, which is what OpenSSL is looking for.
    //
    // See the following DevForums post for more details on this.
    // https://forums.developer.apple.com/message/84684#84684
    //
    // End result looks like this
    // https://lapo.it/asn1js/#3059301306072A8648CE3D020106082A8648CE3D030107034200041F4E3F6CD8163BCC14505EBEEC9C30971098A7FA9BFD52237A3BCBBC48009162AAAFCFC871AC4579C0A180D5F207316F74088BF01A31F83E9EBDC029A533525B
    //
    public lazy var DER: Data = {
        var x9_62HeaderECHeader = [UInt8]([
            /* sequence          */ 0x30, 0x59,
            /* |-> sequence      */ 0x30, 0x13,
            /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
            /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
            /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
            ])
        var result = Data()
        result.append(Data(x9_62HeaderECHeader))
        result.append(self.raw)
        return result
    }()
    
    public lazy var PEM: String = {
        var lines = String()
        lines.append("-----BEGIN PUBLIC KEY-----\n")
        lines.append(self.DER.base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
        lines.append("\n-----END PUBLIC KEY-----")
        return lines
    }()
    
    internal init(_ raw: Data) {
        self.raw = raw
    }
}
