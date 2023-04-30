import random

def text2ints(text, m):
    t = text.encode() + b"\x00" * (m - (len(text) % m))
    return [int.from_bytes(t[i:i+m], "big") for i in range(0, len(t), m)]

def ints2text(ints, m):
    return b"".join([i.to_bytes(m, "big") for i in ints]).decode()

def xgcd(a, b):
    if b == 0:
        g, x, y = a, 1, 0
    else:
        g, y, x = xgcd(b, a % b)
        y -= x * (a // b)
        
    return g, x, y

def gcd(a, b):
    return a if b == 0 else gcd(b, a % b)

def generate_keypair(p, q):
    n = p * q
    phi = (p-1) * (q-1)

    e = random.randint(2, phi-1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi-1)
    
    d = xgcd(e, phi)[1] % phi

    return (e, n), (d, n)

def encrypt(pubkey, plaintext):
    b = find_blocksize(pubkey[1])
    return [pow(i, pubkey[0], pubkey[1]) for i in text2ints(plaintext, b)]


def decrypt(seckey, ciphertext):
    b = find_blocksize(seckey[1])
    return ints2text([pow(i, seckey[0], seckey[1]) for i in ciphertext], b)

def find_blocksize(n):
    b = 1
    while pow(2, (8*(b+1)))-1 < n:
        b += 1
    return b

if __name__ == "__main__":
    prime_1, prime_2 = 1048583, 1299827
    pubkey, seckey = generate_keypair(prime_1, prime_2)
    message = "A super secret message!"
    encrypted_msg = encrypt(pubkey, message)
    print(f"Encrypted message: {encrypted_msg}")
    decrypted_msg = decrypt(seckey, encrypted_msg)
    print(f"Decrypted message: {decrypted_msg}")
