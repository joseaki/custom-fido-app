//
//  COSE.swift
//  matrix
//
//  Created by Antonio Alanya on 30/03/24.
//

import Foundation

internal struct COSEKeyFieldType {
    static let kty:    Int =  1
    static let alg:    Int =  3
    static let crv:    Int = -1
    static let xCoord: Int = -2
    static let yCoord: Int = -3
    static let n:      Int = -1
    static let e:      Int = -2
}

internal struct COSEKeyCurveType {
    static let p256:    Int = 1
    static let p384:    Int = 2
    static let p521:    Int = 3
    static let x25519:  Int = 4
    static let x448:    Int = 5
    static let ed25519: Int = 6
    static let ed448:   Int = 7
}

internal struct COSEKeyType {
    static let ec2: UInt8 = 2
    static let rsa: UInt8 = 3
}

public enum COSEAlgorithmIdentifier: Int, Codable {
    // See https://www.iana.org/assignments/cose/cose.xhtml#algorithms

    case rs256 = -257
    case rs384 = -258
    case rs512 = -259
    case es256 =   -7
    case es384 =  -35
    case es512 =  -36
    case ed256 = -260
    case ed512 = -261
    case ps256 =  -37
    
    public static func fromInt(_ num: Int) -> Optional<COSEAlgorithmIdentifier> {
        switch num {
        case self.rs256.rawValue:
            return self.rs256
        case self.rs384.rawValue:
            return self.rs384
        case self.rs512.rawValue:
            return self.rs512
        case self.es256.rawValue:
            return self.es256
        case self.es384.rawValue:
            return self.es384
        case self.es512.rawValue:
            return self.es512
        case self.ed256.rawValue:
            return self.ed256
        case self.ed512.rawValue:
            return self.ed512
        case self.ps256.rawValue:
            return self.ps256
        default:
            return nil
        }
    }

    public static func ==(
        lhs: COSEAlgorithmIdentifier,
        rhs: COSEAlgorithmIdentifier) -> Bool {

        switch (lhs, rhs) {
        case (.es256, .es256):
            return true
        case (.es384, .es384):
            return true
        case (.es512, .es512):
            return true
        case (.rs256, .rs256):
            return true
        case (.rs384, .rs384):
            return true
        case (.rs512, .rs512):
            return true
        case (.ed256, .ed256):
            return true
        case (.ed512, .ed512):
            return true
        case (.ps256, .ps256):
            return true
        default:
            return false
        }

    }
}

internal class COSEKeyParser {

    public static func parse(bytes: [UInt8]) -> Optional<(COSEKey, Int)>{

        let reader = CBORReader(bytes: bytes)

        guard let params = reader.readIntKeyMap() else {
            FidoLogger.debug("<COSEKeyParser> failed to read CBOR IntKeyMap")
            return nil
        }

        let readSize = reader.getReadSize()

        guard let kty = params[Int64(COSEKeyFieldType.kty)] as? UInt8 else {
            FidoLogger.debug("<COSEKeyParser> 'kty' not found")
            return nil
        }

        guard let alg = params[Int64(COSEKeyFieldType.alg)] as? Int else {
            FidoLogger.debug("<COSEKeyParser> 'alg' not found")
            return nil
        }

        if kty == COSEKeyType.rsa {

            guard let n = params[Int64(COSEKeyFieldType.n)] as? [UInt8] else {
                FidoLogger.debug("<COSEKeyParser> 'n' not found")
                return nil
            }

            if n.count != 256 {
                FidoLogger.debug("<COSEKeyParser> 'n' should be 256 bytes")
                return nil
            }

            guard let e = params[Int64(COSEKeyFieldType.e)] as? [UInt8] else {
                FidoLogger.debug("<COSEKeyParser> 'e' not found")
                return nil
            }

            if e.count != 3 {
                FidoLogger.debug("<COSEKeyParser> 'e' should be 3 bytes")
                return nil
            }

            let key = COSEKeyRSA(
                alg: alg,
                n:   n,
                e:   e
            )

            return (key, readSize)

        } else if kty == COSEKeyType.ec2 {

            guard let crv = params[Int64(COSEKeyFieldType.crv)] as? Int else {
                FidoLogger.debug("<COSEKeyParser> 'crv' not found")
                return nil
            }

            guard let x = params[Int64(COSEKeyFieldType.xCoord)] as? [UInt8] else {
                FidoLogger.debug("<COSEKeyParser> 'xCoord' not found")
                return nil
            }

            if x.count != 32 {
                FidoLogger.debug("<COSEKeyParser> 'xCoord' should be 32 bytes")
                return nil
            }

            guard let y = params[Int64(COSEKeyFieldType.yCoord)] as? [UInt8] else {
                FidoLogger.debug("<COSEKeyParser> 'yCoord' not found")
                return nil
            }

            if y.count != 32 {
                FidoLogger.debug("<COSEKeyParser> 'yCoord' should be 32 bytes")
                return nil
            }

            let key = COSEKeyEC2(
                alg:    alg,
                crv:    crv,
                xCoord: x,
                yCoord: y
            )

            return (key, readSize)

        } else {
            FidoLogger.debug("<COSEKeyParser> unsupported 'kty': \(kty)")
            return nil
        }
    }

}

public protocol COSEKey {
    func toBytes() -> [UInt8]
}

internal struct COSEKeyRSA : COSEKey {

    var alg: Int
    var n: [UInt8] // 256 bytes
    var e: [UInt8] //   3 bytes

    public func toBytes() -> [UInt8] {

        let dic = SimpleOrderedDictionary<Int>()
        dic.addInt(COSEKeyFieldType.kty, Int64(COSEKeyType.rsa))
        dic.addInt(COSEKeyFieldType.alg, Int64(self.alg))
        dic.addBytes(COSEKeyFieldType.n, self.n)
        dic.addBytes(COSEKeyFieldType.e, self.e)

        return CBORWriter()
            .putIntKeyMap(dic)
            .getResult()
    }

}

internal struct COSEKeyEC2 : COSEKey {

    var alg: Int
    var crv: Int
    var xCoord: [UInt8] // 32 bytes
    var yCoord: [UInt8] // 32 bytes

    public func toBytes() -> [UInt8] {

        let dic = SimpleOrderedDictionary<Int>()
        dic.addInt(COSEKeyFieldType.kty, Int64(COSEKeyType.ec2))
        dic.addInt(COSEKeyFieldType.alg, Int64(self.alg))
        dic.addInt(COSEKeyFieldType.crv, Int64(self.crv))
        dic.addBytes(COSEKeyFieldType.xCoord, self.xCoord)
        dic.addBytes(COSEKeyFieldType.yCoord, self.yCoord)
        
        return CBORWriter()
            .putIntKeyMap(dic)
            .getResult()
    }
}
