//
//  Logger.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation

public class FidoLogger {

    public static var available: Bool = false

    public static func debug(_ msg: String) {
        if available {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyyMMddHHmmss"
            let dateString = formatter.string(from: Date())
            print("\(dateString) [FidoLogger]" + msg)
        }
    }
}
