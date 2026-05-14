import base64

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Output dari tantangan
c_flag_b64 = b'uPFkG+d2LPMyzKebNR/kIaOvHSHQRQCtvbRfABhTVrLs93jbAjXJkPRA1P/UUuuM'
c2_b64 = b'o99bMslQHZoL2LawOxOqLK6tAF7UTRCK1tVQMixxcJTS1WTaGSKbuPhN1/jFWKOQ'

# Plaintext yang diketahui (P2)
p2 = b"Welcome to the land of P4 JakartaTimur Indonesia"

# Decode base64 ciphertext
c_flag = base64.b64decode(c_flag_b64)
c2 = base64.b64decode(c2_b64)

# Hitung Keystream dari P2 dan C2
keystream = xor(p2, c2)

# Dekripsi Flag dengan Keystream tersebut
flag = xor(c_flag, keystream)
print(flag.decode())

