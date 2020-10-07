#!/usr/bin/env python3

import argparse, re
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

UUIDV4_PATTERN = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
ENCRYPT_SUBPARSER = 'encrypt'
DECRYPT_SUBPARSER = 'decrypt'
MIN_MAC_LENGTH = 6

# UUIDify(3DES-CFB(key0, iv, data) || truncated(HMAC(key1, data)))
# https://tools.ietf.org/html/rfc4122#section-4.1

def encrypt(data):
    key0 = DES3.adjust_key_parity(get_random_bytes(24))
    key1 = get_random_bytes(32) 
    cipher = DES3.new(key0, DES3.MODE_CFB)
    ciphertext = cipher.encrypt(data.encode())
    
    mac = HMAC.new(key1, digestmod=SHA256)
    mac.update(data.encode())

    available_mac_length = 31 - len(cipher.iv.hex()) - len(ciphertext.hex()) # account for the v4 const in the UUID
    if available_mac_length < MIN_MAC_LENGTH:
        raise argparse.ArgumentTypeError('Input data is too long') 
    
    truncated_mac_hex = mac.hexdigest()[0:available_mac_length]
    iv_hex = cipher.iv.hex()
    ct_hex = ciphertext.hex()

    result = f'iv: {iv_hex} ({len(iv_hex)})\nciphertext: {ct_hex} ({len(ct_hex)})\nmac: {truncated_mac_hex} ({len(truncated_mac_hex)})\n'
    print(f'Please save this composite encryption key:\n{key0.hex()}{key1.hex()}')
    print()
    print(result)

def decrypt(uuid, key, iv):
    print(uuid,key,iv)

def uuidv4(arg_value, pat=UUIDV4_PATTERN):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError('Invalid UUIDv4 input')
    return arg_value

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='subparser')

encrypt_parser = subparsers.add_parser(ENCRYPT_SUBPARSER)
encrypt_parser.add_argument('-d', '--data', type=str, required=True)

decrypt_parser = subparsers.add_parser(DECRYPT_SUBPARSER)
decrypt_parser.add_argument('-u', '--uuidv4', type=uuidv4, required=True)
decrypt_parser.add_argument('-k', '--key', type=str, required=True)
decrypt_parser.add_argument('-iv', '--initialization-vector', type=str, required=True)

args = parser.parse_args()

if ENCRYPT_SUBPARSER == args.subparser:
    encrypt(args.data)
if DECRYPT_SUBPARSER == args.subparser:
    decrypt(args.uuid, args.key, args.iv)
