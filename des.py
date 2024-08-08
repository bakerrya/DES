import time
import random

round_keys = []

def pad_text(text):
    text_length = (8 - len(text) % 8) % 8
    padded_text = text + ('\0' * text_length)
    return padded_text

def convert_text(blocks):
    int_64 = 0
    for block in blocks:
        for char in block:
            int_64  = (int_64 << 8) | ord(char)
    
    print("printing converted text", int_64)
    return int_64

def num_to_ascii(num):
    ascii_str = ""
    for _ in range(8):
        ascii_char = chr(num & 0xFF)
        ascii_str = ascii_char + ascii_str
        num >>= 8
    return ascii_str
    
def encrypt(plaintext, key):
    res = ""
    padded_text = pad_text(plaintext)
    blocks = [padded_text[i:i+8] for i in range(0, len(padded_text), 8)]
    for i in range(len(blocks)):
        num = convert_text(blocks[i])
        encrypted_block = des(num, key, "encrypt")
        encrypted_ascii = num_to_ascii(encrypted_block)
        res += encrypted_ascii
    return res

def decrypt(encrypted_text, key):
    res = ""
    padded_text = pad_text(encrypted_text)
    blocks = [padded_text[i:i+8] for i in range(0, len(padded_text), 8)]
    for i in range(len(blocks)):
        num = convert_text(blocks[i])
        decrypted_block = des(num, key, "decrypt")
        decrypted_ascii = num_to_ascii(decrypted_block)
        res += decrypted_ascii
    return res

def pc2(key_56):
    PC2_table = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    pc2_key = 0
    for i in range(48):
        bit_position = 56 - PC2_table[i]
        bit_value = (key_56 >> bit_position) & 1
        pc2_key |= bit_value << (47 - i)
        
    return pc2_key

def initial_permutation(num):
    initial_permutation_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    permuted_num = 0
    for i in range(64):
        bit_position = 64 - initial_permutation_table[i]
        bit_value = (num >> bit_position) & 1
        permuted_num |= bit_value << i
    return permuted_num
    
def round_function(right_half, round_key):
    expansion_table = [
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    ]
    sbox = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
    ]
    
    expanded_right_half = 0

    for i in range(48):
        bit_pos = 32 - expansion_table[i]
        value = (right_half >> bit_pos) & 1
        expanded_right_half |= value << (47 - i)

    xor_result = expanded_right_half ^ round_key
    
    sbox_result = 0
    
    for i in range(8):
        block = (xor_result >> (42 - 6 * i)) & 0x3F
        row = ((block >> 5) << 1) | (block & 1)
        col = (block >> 1) & 0xF
        sbox_value = sbox[0][row][col]
        sbox_result |= sbox_value << (28 - 4 * i)

    intermediary_permutation_table = [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    ]
    permuted_sbox_result = 0
    for i in range(32):
        bit_position = 32 - intermediary_permutation_table[i]
        bit_value = (sbox_result >> bit_position) & 1
        permuted_sbox_result |= bit_value << (31 - i)

    next_right_half = permuted_sbox_result ^ right_half
    print("next right half ", format(next_right_half, "064b"))
    return next_right_half

def des(num, key_56, choice):
    round_keys = []
    
    num = initial_permutation(num)
    
    for _ in range(16):
        key_56 <<= 1
        round_key = pc2(key_56)
        round_keys.append(round_key)

    if choice == "encrypt":
        for i in range(16):
            left_half = num >> 32
            right_half = num & 0xFFFFFFFF
            next_right_half = round_function(right_half, round_keys[i])
            num = (next_right_half << 32) | left_half
    elif choice == "decrypt":
        round_keys.reverse() 
        for i in range(16):
            left_half = num >> 32
            right_half = num & 0xFFFFFFFF
            next_right_half = round_function(right_half, round_keys[i])
            num = (next_right_half << 32) | left_half
    
    # Final permutation
    permuted_num = 0
    final_permutation_table = [
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    ]
    for i in range(64):
        bit_position = 64 - final_permutation_table[i]
        bit_value = (num >> bit_position) & 1
        permuted_num |= bit_value << i

    return permuted_num
 
if __name__ == "__main__":
    current_time = int(time.time())
    random.seed(current_time)

    print("DES Implementation:\n")
    while True:
        plaintext = input('Enter text to encrypt ("Exit" to quit): ')
        if plaintext.lower() == "exit":
            break
        
        key = random.getrandbits(56)
        
        encrypted_text = encrypt(plaintext, key)
        decrypted_text = decrypt(encrypted_text, key)
        print(f"Encrypted text: {encrypted_text}")
        print(f"Decrypted text: {decrypted_text}")

