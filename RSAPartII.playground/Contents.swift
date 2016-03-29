/*:
 # CS 190 Problem Set #7&mdash;RSA Cryptography Part II
 
 [Course Home Page]( http://physics.stmarys-ca.edu/classes/CS190_S16/index.html )
 
 Due: Tuesday, April 12th, 2016.
 
 ## Reading that is Related to this Week's Lectures and/or This Problem Set
 
 This is Part II of the RSA Cryptography Problem Set begun last week.
 
 For this problem set, we are going to finish Rivest-Shamir-Adleman (RSA) cryptography following the Wikibook [A Basic Public Key Example]( https://en.wikibooks.org/wiki/A_Basic_Public_Key_Example ). For convenience I snarfed a printable copy of the first six sections into cs190-ps6.
 
 In my implementation of RSA.publicKey(), you'll see that I used the coprimes utility you implemented last week.
 
 ## Directions Specific to this Problem Set
 
 I have implemented a couple of important methods on the class RSA, specifically: RSA.publicKey() and RSA.encrypt().
 
 Your job is to implement the following two methods on the class RSA:
 
 1. (3 pts) RSA.privateKey() -> PrivateKey
 
 2. (2 pts) RSA.decrypt(cipherValue: Int) -> Int
 
 If you do them correctly, all the unit tests will pass.
 
 I am not going to pretend these two problems are easy. They are short, but they are hard because:
 
 * You have to read and understand the section titled "Making Site B's Private KEY" to implement RSA.privateKey().
 * You have to read and understand the section titled "Decryption with B's Private Key" to implement RSA.decrypt().
 * You have to read and understand most of the material prior to those sections.
 
 ## General Directions for all Problem Sets
 
 1. Fork this repository to create a repository in your own Github account. Then clone your fork to whatever machine you are working on.
 
 2. These problem sets are created with the latest version of Xcode and Mac OS X: Xcode 7.3 and OS X 10.11.4. I haven't tested how well this problem set will work under Xcode 7.2.1. Please go into Galileo 205, 206 or 208 and test your work rather than relying on the Xcode 7.2.1 machines in Garaventa.
 
 3. Under no circumstances copy-and-paste any part of a solution from another student in the class. Also, under no circumstances ask outsiders on Stack Exchange or other programmers' forums to help you create your solution. It is however fine&mdash;especially when you are truly stuck&mdash;to ask others to help you with your solution, provided you do all of the typing. They should only be looking over your shoulder and commenting. It is of course also fine to peruse StackExchange and whatever other resources you find helfpul.
 
 4. Your solution should be clean and exhibit good style. At minimum, Xcode should not flag warnings of any kind. Your style should match Apple's as shown by their examples and declarations. Use the same indentation and spacing around operators as Apple uses. Use their capitalization conventions. Use parts of speech and grammatical number the same way as Apple does. Use descriptive names for variables. Avoid acronyms or abbreviations. I am still coming up to speed on good Swift style. When there appears to be conflict my style and Apple's, copy Apple's, not mine.
 
 5. When completed, before the class the problem set is due, commit your changes to your fork of the repository. I should be able to simply clone your fork, build it and execute it in my environment without encountering any warnings, adding any dependencies or making any modifications.
 
 ## Implementations from Last Week's Problem Set.
 */
// Returns an array of booleans of length highest, where each boolean says whether that number is prime.
func sieveOfEratosthenes(highest: Int) -> [Bool] {
    // Initially the sieve is agnostic as to whether any number is prime or not (initialized to all nil):
    var sieve = [Bool?](count: highest, repeatedValue: nil)
    // By convention, 0 and 1 are not prime, so we can mark those:
    sieve[0] = false
    sieve[1] = false
    var idx = 2
    repeat {
        // Increment the index until we come to one that is not marked:
        while idx < highest && sieve[idx] != nil {
            idx += 1
        }
        // Either we found another prime or we completed the search:
        if idx < highest {
            // found another prime
            sieve[idx] = true
            // now mark all multiples of that prime as non-prime
            var idx2 = 2 * idx
            while idx2 < highest {
                sieve[idx2] = false
                idx2 += idx
            }
        } else {
            // completed the search
            break
        }
    } while true
    return sieve.map { $0! } // this last is just to unwrap Bool? to Bool
}

// This function just uses the previous one, and returns the result in a more user-friendly form.
func primes(highest: Int) -> [Int] {
    let sieve = sieveOfEratosthenes(highest)
    var result: [Int] = []
    for i in 0 ..< highest {
        if sieve[i] == true {
            result.append(i)
        }
    }
    return result
}

func factor(h: Int, candidates: [Int]) -> Int? {
    for candidate in candidates {
        if h % candidate == 0 {
            return candidate
        }
    }
    return nil
}

func factors(g: Int, candidates: [Int]) -> [Int] {
    var result: [Int] = []
    var residual = g
    repeat {
        let found = factor(residual, candidates: candidates)
        if found != nil {
            residual = residual / found!
            result.append(found!)
        } else {
            break
        }
    } while true
    return result
}

func factors(g: Int) -> [Int] {
    let highest = Int(sqrt(Double(g)))
    let candidates = primes(highest + 1)
    return factors(g, candidates: candidates)
}

// This function returns all coprimes of a given integer f that are smaller than f
func coprimes(f: Int) -> [Int] {
    var result: [Int] = []
    let candidateFactors = factors(f)
    for candidateCoprime in 2..<f {
        if factors(candidateCoprime, candidates: candidateFactors).isEmpty {
            result.append(candidateCoprime)
        }
    }
    return result
}

protocol Crypto {
    
    // encrypts plain value and returns cipher value
    func encrypt(plainValue: Int) -> Int
    
    // decrypts cipher value and returns the plain value
    func decrypt(cipherValue: Int) -> Int
    
}

struct PublicKey {
    let encryptionExponent: Int
    let modulus: Int
}

struct PrivateKey {
    let decryptionExponent: Int
    let modulus: Int
}

class RSA: Crypto {
    
    let p: Int // In the article example, the first prime is 5.
    let q: Int // In the article example, the second prime is 11.
    
    init(p: Int, q: Int) {
        self.p = p
        self.q = q
    }
/*:
 ## Implementation of RSA.publicKey() and RSA.encrypt() */
    // The public key is used for encryption.
    func publicKey() -> PublicKey {
        let modulus = p * q // In the article example, this turns out to be 55.
        let f_n = (p - 1) * (q - 1) // In the article example, this turns out to be 40.
        // **** The following line is where we use all the utilities we built last week. **** //
        let coprimeOptions = coprimes(f_n)
        // **** The following line is hokey -- it's this way just to follow the example. **** //
        let encryptionExponent = coprimeOptions[1] // In the example, the 2nd coprime is chosen.
        // **** There is an entire paragraph in the documentation we are following about choosing the coprime carefully: "It will have been noted by some that the same number can result for both the encrypt and decrypt exponents. This particular case must be avoided by deliberate testing since a hacker would likely test for this possibility early in the process of an attack. In the above examples, this would have been the case if 9, 11, 21, 33 or 39 were chosen for the public key instead of some other. Lest it be thought that anticipation of this error is simple, notice that even in this set that both coprimes that are themselves prime (eg; leading to: 11 * 11 = 1 mod 40), and those that are coprime but not in themselves prime (eg; 9, 21, 33, and 39), can all produce this insecure state of affairs." **** //
        return PublicKey(encryptionExponent: encryptionExponent, modulus: modulus)
    }
    
    // Encrypts plainValue using the public key. Returns the cipher text.
    func encrypt(plainValue: Int) -> Int {
        let publicKey = self.publicKey()
        var exponentiated = 1
        for _ in 0 ..< publicKey.encryptionExponent {
            exponentiated *= plainValue
        }
        return exponentiated % publicKey.modulus
    }
    
/*:
 ## Implementation of RSA.privateKey() and RSA.decrypt() */
    // The private key is used for decryption.
    func privateKey() -> PrivateKey {
        return PrivateKey(decryptionExponent: 2, modulus: 3)
    }
    
    // Decrypts cipherValue using the private key. Returns the plain value.
    func decrypt(cipherValue: Int) -> Int {
        return 0
    }
    
}
/*:
 ## Unit tests that Run Automatically */
import XCTest

class CryptoTestSuite: XCTestCase {
    
    // Test the primes less than 20
    func testPrimes() {
        let expectedPrimes = [2, 3, 5, 7, 11, 13, 17, 19]
        let primesLessThan20 = primes(20)
        XCTAssertEqual(expectedPrimes, primesLessThan20, "Mismatch in list of primes less than 20.")
    }
    
    // Given the candidate factors [3, 8, 11], find an 8 in 1408.
    func testFactorFound() {
        let result = factor(1408, candidates: [3, 8, 11])
        let expectedResult = 8
        XCTAssertEqual(expectedResult, result, "Mismatch in factor in 1408.")
    }
    
    // Given the candidate factors [3, 8, 11], find no factor of 1409.
    func testFactorNotFound() {
        let result = factor(1409, candidates: [3, 8, 11])
        let expectedResult: Int? = nil
        XCTAssertEqual(expectedResult, result, "Mismatch in factor of 1409.")
    }
    
    // Given the candidate factors [3, 8, 11], factor 4224 into 3 * 8 * 8 * 11.
    // The remaining factor of 2 is not among the candidates and will not be found.
    func testFactorsGivenCandidates() {
        let result = factors(4224, candidates: [3, 8, 11])
        let expectedResult = [3, 8, 8, 11]
        XCTAssertEqual(expectedResult, result, "Mismatch in factors of 4224.")
    }
    
    // Factor 25 into 5 * 5.
    func testFactorsPerfectSquare() {
        let result = factors(25)
        let expectedResult = [5, 5]
        XCTAssertEqual(expectedResult, result, "Mismatch in factors of 25.")
    }
    
    // Factor 4224 into 2 * 2 * 2 * 2 * 2 * 2 * 2 * 3 * 11.
    func testFactors() {
        let result = factors(4224)
        let expectedResult = [2, 2, 2, 2, 2, 2, 2, 3, 11]
        XCTAssertEqual(expectedResult, result, "Mismatch in factors of 4224.")
    }
    
    // Test the coprimes of 40.
    func testCoprimes() {
        // These are the expected coprimes of 40 according to the documentation we are following.
        let expectedCoprimes = [3, 7, 9, 11, 13, 17, 19, 21, 23, 27, 29, 31, 33, 37, 39]
        let coprimesOf40 = coprimes(40)
        XCTAssertEqual(expectedCoprimes, coprimesOf40, "Mismatch in list of coprimes of 40.")
    }
    
    // Test the public key example given in the documentation.
    func testPublicKey() {
        let rsaExample = RSA(p: 5, q: 11)
        let result = rsaExample.publicKey()
        let expectedEncryptionExponent = 7
        let expectedModulus = 55
        XCTAssertEqual(expectedEncryptionExponent, result.encryptionExponent, "Mismatch in public key encryption exponent.")
        XCTAssertEqual(expectedModulus, result.modulus, "Mismatch in public key modulus.")
    }
    
    // Test the private key example given in the documentation.
    func testPrivateKey() {
        let rsaExample = RSA(p: 5, q: 11)
        let result = rsaExample.privateKey()
        let expectedDecryptionExponent = 23
        let expectedModulus = 55
        XCTAssertEqual(expectedDecryptionExponent, result.decryptionExponent, "Mismatch in private key decryption exponent.")
        XCTAssertEqual(expectedModulus, result.modulus, "Mismatch in private key modulus.")
    }
    
    // Test another private key.
    func testPrivateKeyTwo() {
        let rsaExample = RSA(p: 5, q: 13)
        let result = rsaExample.privateKey()
        let expectedDecryptionExponent = 7
        let expectedModulus = 65
        XCTAssertEqual(expectedDecryptionExponent, result.decryptionExponent, "Mismatch in private key decryption exponent.")
        XCTAssertEqual(expectedModulus, result.modulus, "Mismatch in private key modulus.")
    }
    
    // Test encrypt 2 becomes 18.
    func testEncrypt() {
        let rsaExample = RSA(p: 5, q: 11)
        let encryptedValue = rsaExample.encrypt(2)
        let expectedValue = 18
        XCTAssertEqual(expectedValue, encryptedValue, "Mismatch in encrypted value.")
    }
    
    // Test decrypt 3 becomes 27.
    func testDecrypt3() {
        let rsaExample = RSA(p: 5, q: 11)
        let decryptedValue = rsaExample.decrypt(3)
        let expectedValue = 27
        XCTAssertEqual(expectedValue, decryptedValue, "Mismatch in decrypted value.")
    }
    
    // Test decrypt 4 becomes 9.
    func testDecrypt4() {
        let rsaExample = RSA(p: 5, q: 11)
        let decryptedValue = rsaExample.decrypt(4)
        let expectedValue = 9
        XCTAssertEqual(expectedValue, decryptedValue, "Mismatch in decrypted value.")
    }
    
}
/*:
 The last bit of arcana is necessary to support the execution of unit tests in a playground, but isn't documented in [Apple's XCTest Library]( https://github.com/apple/swift-corelibs-xctest ). I gratefully acknowledge Stuart Sharpe for sharing it in his blog post, [TDD in Swift Playgrounds]( http://initwithstyle.net/2015/11/tdd-in-swift-playgrounds/ ). */
class PlaygroundTestObserver : NSObject, XCTestObservation {
    @objc func testCase(testCase: XCTestCase, didFailWithDescription description: String, inFile filePath: String?, atLine lineNumber: UInt) {
        print("Test failed on line \(lineNumber): \(description)")
    }
}

XCTestObservationCenter.sharedTestObservationCenter().addTestObserver(PlaygroundTestObserver())

CryptoTestSuite.defaultTestSuite().runTest()

