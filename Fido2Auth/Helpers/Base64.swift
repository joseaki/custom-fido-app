//
//  Base64.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation

public class Base64 {
    public static func encodeBase64(_ bytes: [UInt8]) -> String {
        return encodeBase64(Data(_: bytes))
    }
    
    public static func encodeBase64(_ data: Data) -> String {
        return data.base64EncodedString()
    }

    public static func encodeBase64URL(_ bytes: [UInt8]) -> String {
        return encodeBase64URL(Data(_: bytes))
    }

    public static func encodeBase64URL(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

}
