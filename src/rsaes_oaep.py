
import os
from hashlib import sha1,sha224,sha256
from src.primitives import i2osp, os2ip, mgf1,sha256
class OAEP: #OAEP Padding
    def __init__(self, n_len, rsa_core):
        """Initialize OAEP parameters
        n_len: length in octets of the RSA modulus n
        rsa_core: instance of the RSACore class
        hash_algorithm: the hash function to be used (sha1, sha224, sha256)
        """
        self.k = n_len  # Size of RSA modulus in bytes
        self.L = b""  # Default empty label
        self.rsa_core = rsa_core

    def rsaes_oaep_encrypt(self, public_key, M, L=b''):
        """
        RSAES-OAEP-ENCRYPT((n, e), M, P) operation.
        public_key: (n, e) tuple
        message (M): an octet string to be encrypted
        label (L): optional label, an octet string
        Return ciphertext (C), an octet string

        Input:
        1.  Public Key - (e, n) recipients RSA public key
        2.  M - message to be encrypted, an octet string of length at most k - 2 - 2*hLen, where k is the length in 
        octets of the modulus n and hLen is the length in octets of the hash function output for EME-OAEP.
        3.  L -  encoding parameters, an octet string that may be empty
    Output:
         1. C - ciphertext, an octet string of length k
    Errors: 1. message too long
    Assumption: public key (n, e) is valid
        """
        # EME-OAEP encoding
        EM = self.encode(M,self.k, L)
        print(f"EM Length: {len(EM)}, k (modulus size): {self.k}")


        # Convert EM to an integer message representative m
        m = os2ip(EM)
        print(f"m: {m}")
        # Apply the RSAEP encryption primitive
        c = self.rsa_core.rsaep(public_key, m)
        print(f"c: {c}")

        # Convert the ciphertext representative c to a ciphertext C
        C = i2osp(c, self.k)
        print(f"C: {C}")

        return C

    def encode(self, M,emLen, L=b'', hash=sha256, mgf=mgf1) -> bytes:
        """EME-OAEP encoding operation'(Section 7.1.1)
        message (M): an octet string to be encoded
        L: optional label, an octet string
        Return encoded message (EM), an octet string

        Inputs:
            - M: message to be encoded, an octet string of length at most (emLen - 1 - 2hLen)
            (mLen denotes the length in octets of the message)  
            - L: Encoding Parameters, an octet string
            -emLen: intended length in octets of the encoded message, at least 2hLen + 1
        Options: 
            - Hash hash function (hLen denotes the length in octets of the hash function output)
            - MGF mask generation function
        Output:
            - EM: encoded message, an octet string of length emLen
        Exceptions:
            -Message too long; Parameter string too long
        """
        # 1. If the length of L(lebal) is greater than the input limitation then output ‘‘encoding error’’ and stop.
        # SHA1: 2^61 - 1
        #if len(L) > (pow(2, 61) - 1):
        #     raise ValueError("Encoding error, parameter too large")
        # 1. If the length of L is greater than the input limitation for the hash function
        # (2^61 - 1 octets for SHA-1) then output ‘Encoding error, parameter too large’ and stops.
        M = M
        mLen = len(M)

        lHash = hash(L)
        hLen = len(lHash)
        # PADDING 
        zero_octet = b'\x00'
        PS = zero_octet * (emLen - mLen - 2 * hLen - 2)
        # Create data block
        DB = lHash + PS + b'\x01' + M

        # Generate random seed 
        seed = os.urandom(hLen)

        # Generate masks
        dbMask = mgf(seed, emLen - hLen - 1)
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask)) #Xor

        seedMask = mgf(maskedDB, hLen)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
        # Concatenate everything
        EM = maskedSeed + maskedDB
        #  return EM
        return  EM

    def rsaes_oaep_decrypt(self, private_key, ciphertext, L=b''):
        """
        RSAES-OAEP-DECRYPT(K, C, P) operation.
        ciphertext (C): an octet string to be decrypted
        label (L): optional label, an octet string
        Return decrypted message (M), an octet string

        Inputs: 
            1. K - recipients RSA private_key: (n, d) tuple
            2. C - ciphertext to be decrypted, an octet string of length k
            3. L - encoding parameters, an octet string that may be empty

        Output:
            1. M -  message, an octet string of length at most k - 2 - 2hLen, where hLen is the length in octets
            of the hash function output for EME-OAEP
        Errors:
            1. Decryption error

        """
        cLen = len(ciphertext)
        # 1. If the length of the ciphertext C is not k octets, output decryption error and stop.
        if cLen != self.k:
            raise ValueError("Decryption error")
        
        # Convert the ciphertext C to an integer ciphertext representative c
        c = os2ip(ciphertext)

        # Apply the RSADP decryption primitive
        m = self.rsa_core.rsadp(private_key, c)

        # Convert the message representative m to an encoded message EM
        EM = i2osp(m, self.k)

        # EME-OAEP decoding
        try:
            M = self.decode(EM, L)
        except ValueError:
            raise ValueError("Descryption error")
        # Output the message M
        return M

    def decode(self, EM, L=b'', hash=sha256, mgf=mgf1) -> bytes:
        """EME-OAEP-decoding(EM, P)(Section 7.1.2)
        EM: encoded message, an octet string
        L: optional label, an octet string
        Return decoded message (M), an octet string
        
        Options: 
            1. Hash - hash function (hLen denotes the length in octets of the hash function output)
            2. MGF - mask generation function
        Input: 
            1. EM - encoded message, an octet string of length at least 2hLen + 1 (emLen denotes the length in
            octets of EM)
            2. L - Encoding parameters, an octet string
        Output:
            1. M - recovered message, an octet string of length at most emLen - 1 - 2hLen

        Errors:
            1. Decoding error
        
        """

        # 1. If the length of L(lebal) is greater than the input limitation then output ‘‘decoding error’’ and stop.
        # SHA1: 2^61 - 1
        if len(L) > (pow(2, 61) - 1):
            raise ValueError("Decoding error, parameter too large")
        emLen = len(EM)
        lHash = hash(L)
        hLen = len(lHash)
        Y = EM[0]
        maskedSeed = EM[0:hLen]
        maskedDB = EM[hLen + 1:-1]

        # Recover seed
        seedMask = mgf(maskedDB, hLen)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))

        # Recover data block
        dbMask = mgf(seed, emLen - hLen)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))

        # Let pHash = Hash(L), an octet string of length hLen.
        index = DB.find(b'\x01') 
        if DB[:hLen] != lHash:
            raise ValueError("Hash not in DB")
        # Separate DB into an octet string pHash’ || PS || 01 || M
        # 10. return m
        return DB[index:]
