import random


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def is_prime(n, k=5):
    if n <= 1: return False
    for i in range(k):
        a = random.randint(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p


def generate_keypair(bits):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(1, phi)

    public_exponent = gcd(e, phi)
    while public_exponent != 1:
        e = random.randint(1, phi)
        public_exponent = gcd(e, phi)
    d = pow(e, -1, phi)

    return (n, e), (n, d)


def add_zero_padding(plaintext, block_size):
    """Add padding zeros from the plaintext."""
    padding_length = block_size - len(plaintext)
    padding = b"\x00" * padding_length
    return padding + plaintext


def remove_padding(plaintext):
    """Remove padding zeros from the plaintext."""
    # Find the index of the first non-zero byte
    index = next((i for i, byte in enumerate(plaintext) if byte != 0), None)
    if index is not None:
        return plaintext[index:]
    else:
        return b""


def encrypt(public_key, plaintext):
    n, e = public_key
    block_size = (n.bit_length() + 7) // 8
    encrypted_chunks = []

    if len(plaintext) > block_size:
        for i in range(0, len(plaintext), block_size):
            chunk = plaintext[i:i + block_size]
            padded_plaintext = add_zero_padding(chunk.encode(), block_size)
            padded_plaintext_int = int.from_bytes(padded_plaintext, 'big')
            ciphertext = pow(padded_plaintext_int, e, n)
            encrypted_chunks.append(ciphertext)
    else:
        padded_plaintext = add_zero_padding(plaintext.encode(), block_size)
        padded_plaintext_int = int.from_bytes(padded_plaintext, 'big')
        ciphertext = pow(padded_plaintext_int, e, n)
        encrypted_chunks.append(ciphertext)

    return encrypted_chunks


def decrypt(private_key, ciphertext_chunks):
    n, d = private_key
    decrypted_chunks = []
    block_size = (n.bit_length() + 7) // 8
    for chunk in ciphertext_chunks:
        padded_plaintext_int = pow(chunk, d, n)
        padded_plaintext = padded_plaintext_int.to_bytes(block_size, 'big')
        padding_index = padded_plaintext.find(b"\x00", 2)
        if padding_index != -1:
            plaintext = padded_plaintext[padding_index + 1:]
        else:
            plaintext = padded_plaintext
        # Remove trailing zeros
        plaintext = remove_padding(plaintext)
        decrypted_chunks.append(plaintext)
    return b"".join(decrypted_chunks).decode('utf-8')


def save_private_key(private_key, filename):
    with open(filename, 'wb') as f:
        f.write(str(private_key).encode())


def load_private_key(filename):
    with open(filename, 'rb') as f:
        private_key_str = f.read().decode()
        private_key = eval(private_key_str)
    return private_key


if __name__ == "__main__":
    bits = 1024
    public_key, private_key = generate_keypair(bits)
    while True:

        userInput = input(
            "for Encrypting, input TEXT\nfor Decrypting, enter '0'\nfor changing bits length, enter 'bits': ")

        if userInput != '0' and userInput != 'bits' and userInput != '':
            encrypted_message = encrypt(public_key, userInput)
            save_private_key(private_key, '../private_key.txt')
            print("Encrypted message:", encrypted_message)

        elif userInput == 'bits':
            bits = int(input("Enter bits length:"))
            public_key, private_key = generate_keypair(bits)

        elif userInput == '':
            exit()

        else:
            userMessage = input("Please enter your message to decrypt: ")
            ciphertext = [int(char) for char in userMessage.split(',') if char.strip()]
            loaded_private_key = load_private_key('../private_key.txt')
            decrypted_message = decrypt(loaded_private_key, ciphertext)
            print("Decrypted message:", decrypted_message)
