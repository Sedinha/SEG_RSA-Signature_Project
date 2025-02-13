import random
import math
from hashlib import sha3_256
from src.primes import generate_prime_number
from src.utils import bit_len
class RSACore:
    def __init__(self, bits=4096, public_exponent=None):
        """
        Initialize RSA parameters with specified bit length and public exponent.
        bits: length in bits of the RSA modulus n
        public_exponent: RSA public exponent (e)
        """
        self.bits = bits #size of primes in bits
        self.public_exponent = public_exponent #public exponent

    def __generate_e(self, phi, n):
        """ 
        Generate a value for e
        1) 2 < e < phi(n)
        2) has to be co-prime with n and phi(n)
        """
        while True:
            e = random.randrange(2**(self.bits - 1), 2**(self.bits))
            if math.gcd(e, phi) == 1 and math.gcd(e, n) == 1:
                return e

    def generate_keypair(self):
        """
        Generate RSA public and private key pair.
        n = RSA modulus, n = p * q
        e = RSA public exponent
        d = RSA private exponent
        Return (public_key, private_key)
        """
        print("Generating p...")
        p = generate_prime_number()
        print("Generating q...")
        q = generate_prime_number(other_b_len=bit_len(p))
        n = p * q
        phi = (p - 1) * (q - 1)
        # Generate e if not provided
        if self.public_exponent is None:
            self.e = self.__generate_e(phi, n)
        else:
            self.e = self.public_exponent
        # Calculate private key

        d = pow(self.e, -1, phi)

        private_key = (d, n)
        public_key = (self.e, n)
        return public_key, private_key

    def rsaep(self, public_key, m):
        #RSAEP implementation (Section 5.1.1)
        """
        RSA encryption primitive (RSAEP).
        public_key: (n, e) tuple
        m: message representative, an integer between 0 and n-1
        Return ciphertext representative (c)
        """
        # Unpack the public key tuple into modulus (n) and public exponent (e)
        n, e = public_key
        # Check if message representative m is within valid range
        # m must be non-negative (>= 0) and less than modulus n
        if not (0 <= m < n):
            raise ValueError("message representative out of range")
        # Perform RSA encryption operation:
        # c = m^e mod n
        # pow(m, e, n) is Python's built-in modular exponentiation
        # This is more efficient than (m ** e) % n
        return pow(m, e, n)

    def rsadp(self, private_key, c):
        #RSADP implementation (Section 5.1.2)
        """
        RSA decryption primitive (RSADP).
        private_key: (n, d) tuple
        c: ciphertext representative, an integer between 0 and n-1
        Return message representative (m)
        """
        n, d = private_key

        if not (0 <= c < n):
            raise ValueError("ciphertext representative out of range")

        return pow(c, d, n)