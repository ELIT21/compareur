import secrets
import codecs
import hashlib
import base58
import ecdsa
from multiprocessing import Pool

def generate_private_key():
    return secrets.token_hex(32)

def private_key_to_wif(private_key_hex: str) -> str:
    extended_key = "80" + private_key_hex
    first_sha256 = hashlib.sha256(codecs.decode(extended_key, 'hex')).hexdigest()
    second_sha256 = hashlib.sha256(codecs.decode(first_sha256, 'hex')).hexdigest()
    final_key = codecs.decode(extended_key + second_sha256[:8], 'hex')
    return base58.b58encode(final_key).decode('utf-8')

def private_key_to_address(private_key_hex: str) -> str:
    sk = ecdsa.SigningKey.from_string(codecs.decode(private_key_hex, 'hex'), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()
    hash160 = hashlib.new('ripemd160')
    hash160.update(hashlib.sha256(public_key).digest())
    hash160 = hash160.digest()
    return base58.b58encode_check(b"\x00" + hash160).decode('utf-8')

# Optimisation 3: Chargement des adresses depuis le fichier dans un ensemble
with open('bitcoin-v3.txt', 'r') as file:
    addresses_from_file = {line.strip() for line in file}

def check_address(private_key_hex):
    private_key_wif = private_key_to_wif(private_key_hex)
    address = private_key_to_address(private_key_hex)

    # Check for matches and write to find.txt
    if address in addresses_from_file:
        with open('find.txt', 'a') as file:
            file.write(f"Match found:\nPrivate Key WIF: {private_key_wif}\nAddress: {address}\n\n")

address_count = 0
while True:
    private_key_hex = generate_private_key()
    address_count += 1
    print(f"\rGenerated address count: {address_count}", end='', flush=True)

    check_address(private_key_hex)