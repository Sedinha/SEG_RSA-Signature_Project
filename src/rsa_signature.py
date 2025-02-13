import base64
from hashlib import sha256
from src.primitives import i2osp,os2ip,toBase64,fromBase64

class RSASignature:
    def sign(self, M, private_key): # M = message Octet-String primitive 
        """Sign a message using RSA """
        message = M
        hash = int.from_bytes(sha256(message).digest(), 'big')
        signature = pow(hash, private_key[0], private_key[1])
        # encode signature to base64
        # ✅ **Reduzindo o tamanho: armazenamos apenas o hash da assinatura**
        signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, 'big')
        signature_hash = sha256(signature_bytes).digest()  # Apenas 32 bytes

        return base64.b64encode(signature_hash)  # Retorna hash da assinatura em Base64
        signature64 = base64.b64encode(signature_hash)
        return signature64
        

    def verify(self, M, signature, public_key):
        """Verify an RSA signature by checking its hash"""
        message = M
        hash_value = int.from_bytes(sha256(message).digest(), 'big')
        recovered_signature = pow(hash_value, public_key[0], public_key[1])

        # ✅ **Geramos o hash da assinatura recuperada**
        recovered_signature_bytes = recovered_signature.to_bytes((recovered_signature.bit_length() + 7) // 8, 'big')
        recovered_signature_hash = sha256(recovered_signature_bytes).digest()

        return base64.b64decode(signature_hash) == recovered_signature_hash