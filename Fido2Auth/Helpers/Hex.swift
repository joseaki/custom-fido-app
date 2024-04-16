//
//  Hex.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation

func toHexString(_ value: [UInt8]) -> String{
  return value.map{ String(format: "%02x", $0) }.joined()
}
