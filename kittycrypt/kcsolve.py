import binascii
import re

# plaintext from challenge example
plaintext = "You fools! You will never get my catnip!!!!!!!"

# example given
example_cipher_emoji = """🐱‍💻😸😿😼🐱‍👓😺😾😿🙀🐱‍💻🐱‍👓😺😿😹😿🐱‍💻🐱‍👓🐱🐱‍👤😹😿😺🐱‍👓😹🙀😿😾🐱‍🏍🐱‍👓😹😾🐱‍🚀🐱‍👤😾🐱‍💻🐱‍👓😿😽🐱‍👓😺😾🐱‍👤🙀😻🐱‍👓😸🙀😼🐱‍👤🐈🐱‍👓😺🐱‍👤😼😿😾🐱‍👓🐈😿😽🙀🐱‍🚀🐱‍👓😹😾😹🐱‍👤🐱‍👤🐱‍👓😹🙀🐱🐱‍👤😾🐱‍👓🐱🙀😽😿😻🐱‍👓😹🐱‍👤🐱🐱‍👤🐱‍👤🐱‍👓🐈😾😽😿🐱‍💻🐱‍👓🐈🙀🐱‍👓😿🐱‍👤🐱‍👓😹🐱‍👤🐱‍👤😾🐱‍🏍🐱‍👓🐈🐱‍👤🐱😿🐱‍👤🐱‍👓😸😾😿🐱‍👤😾🐱‍💻🐱‍🏍😿🙀🐱‍👓😸😾🙀🙀🐱🐱‍👓😸🐱‍👤🐱‍👓🙀🐱‍👓🐱‍👓🐱🙀🙀😾😺🐱‍👓😺🙀😽😿😸🐱‍👓😸🐱‍👤😾🙀🐈🐱‍👓😺🙀😼🙀😼🐱‍👓😺😿😿😿😿🐱‍🏍😿😾🐱‍👓🐱‍👓😺😿😽😿🐱‍🏍🐱‍👓🐈😾🐈😿😹🐱‍💻😸🐱‍👤😹🐱‍👓😺😿🐱‍👓🙀🐱🐱‍👓😺🙀🐱‍👤😾🐱‍🏍🐱‍👓😹🐱‍👤😸🙀🐱‍🏍🐱‍👓😹🐱‍👤😼🐱‍👤😾🐱‍👓🐱🙀🐈🐱‍👤🐈🐱‍👓😺😿🐱‍👤🐱‍👤😽🐱‍👓😸🐱‍👤🐈🐱‍👤🐱‍🚀🐱‍👓😺🐱‍👤😽🙀😿🐱‍👓😺😿🐱‍💻🙀😿🐱‍👓😺😾🐱‍👤😿🐱‍🚀🐱‍👓😸🙀🐱‍🏍🐱‍👤😻🐱‍👓😸🐱‍👤🐱‍💻🐱‍👤😾🐱‍👓😹😿😻🙀🐱‍🚀🐱‍👓😹😿😿😿😿"""

# ciphered flag emoji string
flag_cipher_emoji = """🐱‍💻😸🙀😼🐱‍👓😺😾😿🐱‍👤🐱🐱‍👓😺😿😹😿🐈🐱‍👓🐱🐱‍👤😺🙀😽🐱‍👓😹🙀😿😾😿🐱‍👓😹😾🐱‍🚀🐱‍👤🐱‍💻🐱‍💻🐱‍👓😾🐱‍👓🐱‍👓😺😾🐱‍👤🐱‍👤😺🐱‍👓😸🙀😼🐱‍👤🐈🐱‍👓😺🐱‍👤😼🙀😽🐱‍👓🐈😿😾🐱‍👤🐱‍🏍🐱‍👓😹😾😹😿😻🐱‍👓😹🙀🐱😾🐱🐱‍👓🐱🙀😼😿🐈🐱‍👓😹🐱‍👤😸😾😾🐱‍👓🐈😾😼😿😿🐱‍👓🐈🙀🐱‍👓🙀😻🐱‍👓😹🐱‍👤🙀🐱‍👤🐱‍🚀🐱‍👓🐈🐱‍👤🐱😿🐈🐱‍👓😸😾🙀🐱‍👤🐈🐱‍💻🐱‍👤🙀😹🐱‍👓😸😾😿🙀🐱‍👓🐱‍👓😸🐱‍👤🐱‍💻🙀🐱‍💻🐱‍👓🐱🙀😿🐱‍👤🐱‍👓🐱‍👓😺🙀😼😿😺🐱‍👓😸🐱‍👤😿🐱‍👤😹🐱‍👓😺🙀😻🐱‍👤😸🐱‍👓😺😿😿🙀😸🐱‍🏍😾😿🐈🐱‍👓😺😿😾😿🐱‍👤🐱‍👓🐈😾🐈😿🐱‍💻🐱‍💻😸🙀😸🐱‍👓😺😿🐱‍👓🐱‍👤😺🐱‍👓😺🙀🙀🙀🐱🐱‍👓😹🐱‍👤😸🙀🙀🐱‍👓😹🐱‍👤😼🐱‍👤🐱‍💻🐱‍👓🐱🙀🐱🐱‍👤😹🐱‍👓😺😿🐱‍🏍😾😹🐱‍👓😸🐱‍👤🐈🙀🐱‍👓🐱‍👓😺🐱‍👤😽🐱‍👤🐱‍👤🐱‍👓😺😿🐱‍🚀😾🐱🐱‍👓😺😾🐱‍🏍🙀🐱‍👓🐱‍👓😸🙀🐱‍💻😾😽🐱‍👓😸🐱‍👤🐱‍👓🐱‍👤🙀🐱‍👓😹😿😼😾😻🐱‍👓😹😿🙀🐱‍👤😻"""

# hex mapping
emoji_to_hex_map = {
    "🐱‍👤": "B",
    "🐱‍🏍": "C",
    "🐱‍💻": "D",
    "🐱‍👓": "E",
    "🐱‍🚀": "F",
    "🐱": "0",
    "🐈": "1",
    "😸": "2",
    "😹": "3",
    "😺": "4",
    "😻": "5",
    "😼": "6",
    "😽": "7",
    "😾": "8",
    "😿": "9",
    "🙀": "A",
}

# regex
pattern = re.compile('|'.join(map(re.escape, emoji_to_hex_map.keys())))

def emojis_to_hex(ciphertext_emoji: str) -> str:
    return pattern.sub(lambda m: emoji_to_hex_map[m.group()], ciphertext_emoji)

def hex_to_keyed_text(hex_string: str) -> str:
    return binascii.unhexlify(hex_string).decode('utf-8')

# key recovery
example_hex = emojis_to_hex(example_cipher_emoji)
example_keyed_text = hex_to_keyed_text(example_hex)
assert len(example_keyed_text) == len(plaintext), "Lengths differ!"

keys = [ord(k) - ord(p) for p, k in zip(plaintext, example_keyed_text)]

# decryption
flag_hex = emojis_to_hex(flag_cipher_emoji)
flag_keyed_text = hex_to_keyed_text(flag_hex)

if len(flag_keyed_text) != len(keys):
    print("keyed text length mismatch")
    print(f"keyed text length: {len(flag_keyed_text)}, length of keys: {len(keys)}")
    exit(1)

flag_plaintext = ''.join([chr(ord(k) - key) for k, key in zip(flag_keyed_text, keys)])

print("recovered key: (length = {}):".format(len(keys)))
print(keys)
print("\nkey plain text:")
print(flag_plaintext)
