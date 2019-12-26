import UIKit
import BigInt

class Paillier: NSObject {
    public class func generateRandomKeys(_ length: UInt!, _ simpleVariant: Bool = false) -> (pk: PaillierPublicKey, sk: PaillierPrivateKey) {
        var p, q, n, phi, n2, g, lambda, mu: BigUInt?
        repeat {
            p = self.generatePrime(length / 2)
            q = self.generatePrime(length / 2)
            n = p! * q!
        } while (n!.bitWidth != length)
        
        phi = (p! - 1) * (q! - 1)
        
        n2 = n!.power(2)
        
        if simpleVariant == true {
            g = n! + 1
            lambda = phi
            mu = lambda?.inverse(n!)
        } else {
            g = self.generator(n!, n2!)
            lambda = self.lcm(p! - 1, q! - 1)
            mu = self.l(g!.power(lambda!, modulus: n2!), n!).inverse(n!);
        }
        
        let publicKey = PaillierPublicKey(
            n: n!,
            n2: n2!,
            g: g!
        )!
        
        let privateKey = PaillierPrivateKey(
            lambda: lambda!,
            mu: mu!,
            p: p!,
            q: q!,
            pk: publicKey
        )!
        
        return (publicKey, privateKey)
    }
    
    public class func generatePrime(_ width: UInt!) -> BigUInt {
        while true {
            var random = BigUInt.randomInteger(withExactWidth: Int(width))
            random |= BigUInt(1)
            if random.isPrime() {
                return random
            }
        }
    }
    
    public class func generator(_ n: BigUInt!, _ n2: BigUInt!) -> BigUInt {
        let alpha = BigUInt.randomInteger(lessThan: n)
        let beta = BigUInt.randomInteger(lessThan: n)
        return ((alpha * n - 1) * (beta.power(n, modulus: n2)).power(BigUInt(1), modulus: n2))
    }
    
    public class func lcm(_ a: BigUInt!, _ b: BigUInt!) -> BigUInt {
        return a * b / a.greatestCommonDivisor(with: b)
    }
    
    public class func l(_ a: BigUInt!, _ n: BigUInt!) -> BigUInt {
        return (a - 1) / n
    }
}

class PaillierPublicKey: NSObject, Codable {
    var n: BigUInt!
    var n2: BigUInt!
    var g: BigUInt!
    
    init?(n: BigUInt!, n2: BigUInt!, g: BigUInt!) {
        self.n = n
        self.n2 = n2
        self.g = g
    }
    
    init?(serialized: [String: Any]) {
        self.n = BigUInt(serialized["n"] as! Data)
        self.n2 = BigUInt(serialized["n2"] as! Data)
        self.g = BigUInt(serialized["g"] as! Data)
    }
    
    public func encrypt(_ m: BigUInt!) -> BigUInt {
        return encryptForZKP(m).c
    }
    
    public func encryptForZKP(_ m: BigUInt!) -> (r: BigUInt, c: BigUInt){
        var r: BigUInt?
        
        repeat {
            r = BigUInt.randomInteger(lessThan: self.n)
        } while (r! <= BigUInt(1))
        
        let c = self.g.power(m, modulus: self.n2) * (r!.power(self.n, modulus: self.n2).power(1, modulus: self.n2))
        
        return (r!, c)
    }
    
    public func encryptWithR(_ m: BigUInt!, _ r: BigUInt!) -> BigUInt {
        return self.g.power(m, modulus: self.n2) * (r.power(self.n, modulus: self.n2).power(1, modulus: self.n2))
    }
    
    public func serialize() -> [String: Any]{
        return [
            "n": n.serialize(),
            "n2": n2.serialize(),
            "g": g.serialize()
        ]
    }
}

class PaillierPrivateKey: NSObject, Codable {
    var lambda: BigUInt!
    var mu: BigUInt!
    var p: BigUInt!
    var q: BigUInt!
    var pk: PaillierPublicKey!
    
    init?(lambda: BigUInt!, mu: BigUInt!, p: BigUInt!, q: BigUInt!, pk: PaillierPublicKey!) {
        super.init()
        
        self.lambda = lambda
        self.mu = mu
        self.p = p
        self.q = q
        self.pk = pk
    }
    
    init?(lambda: BigUInt!, mu: BigUInt!, p: BigUInt!, q: BigUInt!, n: BigUInt!, n2: BigUInt!, g: BigUInt!) {
        super.init()
        
        self.lambda = lambda
        self.mu = mu
        self.p = p
        self.q = q
        self.pk = PaillierPublicKey(n: n, n2: n2, g: g)
    }
    
    init?(serialized: [String: Any]) {
        self.lambda = BigUInt(serialized["lambda"] as! Data)
        self.mu = BigUInt(serialized["mu"] as! Data)
        self.p = BigUInt(serialized["p"] as! Data)
        self.q = BigUInt(serialized["q"] as! Data)
        self.pk = PaillierPublicKey(serialized: serialized["pk"] as! [String: Any])
    }
    
    public func decrypt(_ c: BigUInt!) -> BigUInt {
        return Paillier.l(c.power(self.lambda, modulus: self.pk.n2), (self.pk.n * self.mu).power(1, modulus: self.pk.n))
    }
    
    public func serialize() -> [String: Any] {
        return [
            "lambda": lambda.serialize(),
            "mu": mu.serialize(),
            "p": p.serialize(),
            "q": q.serialize(),
            "pk": pk.serialize()
        ]
    }
}
