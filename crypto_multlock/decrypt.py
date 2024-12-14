import base64
import random
import string

# Polyalphabetic decryption
def polyalphabetic_decrypt(ciphertext_b64, key):
    try:
        key_length = len(key)
        ciphertext = base64.b64decode(ciphertext_b64).decode()

        plaintext = []
        for i, char in enumerate(ciphertext):
            key_char = key[i % key_length]
            decrypted_char = chr((ord(char) - ord(key_char)) % 256)
            plaintext.append(decrypted_char)

        return ''.join(plaintext)
    except Exception as e:
        return None  # In case of any error, return None

# Reverse XOR operation
def reverse_xor(encrypted_bytes, key):
    return ''.join([chr(b ^ key) for b in encrypted_bytes])

# Generate a key from the seed
def generate_key(seed, length=16):
    random.seed(seed)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return key

# Decryption script
def decrypt(hex_string, xor_key, poly_key):
    
    try:
        # Step 1: Convert hex string to bytes
        encrypted_bytes = bytes.fromhex(hex_string)

        # Step 2: Reverse XOR
        base64_encoded = reverse_xor(encrypted_bytes, xor_key)

        # Step 3: Reverse polyalphabetic encryption
        original_string = polyalphabetic_decrypt(base64_encoded, poly_key)

        if original_string is None:
            return None  # If the decryption failed, return None
        
        return original_string
    except Exception as e:
        return None  # Catch any unexpected errors and return None

if __name__ == "__main__":
    
    first_half = []
    second_half = []
    hex_string_1 = "00071134013a3c1c00423f330704382d00420d331d04383d00420134044f383300062f34063a383e0006443310043839004315340314382f004240331c043815004358331b4f3830"

    # Try the first case: xor_key = 42, poly_key between 1 and 1000
    xor_key = 42
    for poly_seed in range(1, 1001):
        poly_key = generate_key(poly_seed)
        decrypted_string = decrypt(hex_string_1, xor_key, poly_key)
        
        if decrypted_string:
            print(f"Found valid decryption with xor_key = {xor_key} and poly_key = {poly_key}")
            print("Decrypted first string:", decrypted_string)
            first_half.append(decrypted_string)

    # Try the second case: xor_key between 1 and 255, poly_key = 42
    for xor_key in range(1, 256):
        poly_key = generate_key(42)
        decrypted_string = decrypt(hex_string_1, xor_key, poly_key)

        if decrypted_string:
            print(f"Found valid decryption with xor_key = {xor_key} and poly_key = {poly_key}")
            print("Decrypted first string:", decrypted_string)
            first_half.append(decrypted_string)
    
    with open('finally.txt', 'w') as f:
        for key in first_half:
            try:
                f.write(f"{key}\n")
            except:
                continue
    
    hex_string_2 = "5d1f486e4d49611a5d1e7e6e4067611f5d5b196e5b5961405d1f7a695b12614e5d58506e4212654b5d5b196e4067611d5d5b726e4649657c5d5872695f12654d5d5b4c6e4749611b"
    
    
    # Try the first case: xor_key = 42, poly_key between 1 and 1000
    xor_key = 42
    for poly_seed in range(1, 1001):
        poly_key = generate_key(poly_seed)
        decrypted_string = decrypt(hex_string_2, xor_key, poly_key)
        
        if decrypted_string:
            print(f"Found valid decryption with xor_key = {xor_key} and poly_key = {poly_key}")
            print("Decrypted second string:", decrypted_string)
            second_half.append(decrypted_string)

    # Try the second case: xor_key between 1 and 255, poly_key = 42
    for xor_key in range(1, 256):
        poly_key = generate_key(42)
        decrypted_string = decrypt(hex_string_2, xor_key, poly_key)

        if decrypted_string:
            print(f"Found valid decryption with xor_key = {xor_key} and poly_key = {poly_key}")
            print("Decrypted second half string:", decrypted_string.encode('utf-8'))
            second_half.append(decrypted_string)
            
    with open('gotit.txt', 'w') as f:
        for key in second_half:
            try:
                f.write(f"{key}\n")
            except:
                continue