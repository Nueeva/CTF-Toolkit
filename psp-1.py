import base64

c_flag_b64 = b'uPFkG+d2LPMyzKebNR/kIaOvHSHQRQCtvbRfABhTVrLs93jbAjXJkPRA1P/UUuuM'
c1_b64     = b'o99bMslQHZoL2LawOxOqLK6tAF7UTRCK1tVQMixxcJTS1WTaGSKbuPhN1/jFWKOQ'
c2_b64     = b'udtOcdJVHZod0uWwcxnsYLasEV7MQl76i5tuPGdkaoWT72jPGHD3usV5mPrFXa+d'

c_flag = base64.b64decode(c_flag_b64)
c1     = base64.b64decode(c1_b64)
c2     = base64.b64decode(c2_b64)

p1 = b"Welcome to the land of P4 JakartaTimur Indonesia"
p2 = b"May the best of you win into the next LKSP level"

# keystream = ciphertext xor plaintext (CTR)
ks1 = bytes(a ^ b for a, b in zip(c1, p1))
ks2 = bytes(a ^ b for a, b in zip(c2, p2))

# gabungkan keystream (kalau flag lebih panjang dari p1/p2, combine coverage)
ks = bytearray(max(len(ks1), len(ks2)))
ks[:len(ks1)] = ks1
for i in range(len(ks2)):
    # kalau posisi belum terisi dari ks1, isi dari ks2
    if ks[i] == 0:
        ks[i] = ks2[i]

# decrypt flag
flag = bytes(a ^ b for a, b in zip(c_flag, ks))
print(flag)
