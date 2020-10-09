#!/usr/bin/env python3

import argparse, re
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# UUIDV4_PATTERN = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
UUIDV4_PATTERN_LOOSE = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[a-f0-9]{4}-?[a-f0-9]{12}\Z', re.I)

ENCRYPT_SUBPARSER = 'encrypt'
DECRYPT_SUBPARSER = 'decrypt'
MIN_MAC_LENGTH = 6

def encrypt(data):
    """
        https://tools.ietf.org/html/rfc4122#section-4.1

        returns UUIDv4 packed in the order of
        ciphertext+mac[0:12] || V4CONST || cipherext+mac[12:] || iv
    """

    key0 = DES3.adjust_key_parity(get_random_bytes(24))
    key1 = get_random_bytes(32) 
    composite_key = key0.hex() + key1.hex()

    cipher = DES3.new(key0, DES3.MODE_CFB)
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    
    mac = HMAC.new(key1, digestmod=SHA256)
    mac.update(data.encode())

    available_mac_length = 31 - len(cipher.iv.hex()) - len(ciphertext.hex()) # account for the v4 const in the UUID
    if available_mac_length < MIN_MAC_LENGTH:
        raise argparse.ArgumentTypeError('Input data is too long') 
    
    truncated_mac_hex = mac.hexdigest()[0:available_mac_length]
    iv_hex = cipher.iv.hex()
    ct_hex = ciphertext.hex()
    pre_const = ct_hex + truncated_mac_hex
    enc_uuid = f'{pre_const[0:8]}-{pre_const[8:12]}-4{pre_const[12:]}-{iv_hex[0:4]}-{iv_hex[4:]}'

    if not UUIDV4_PATTERN_LOOSE.match(enc_uuid):
        raise ValueError("invalid UUIDv4 created")

    return enc_uuid, composite_key

def decrypt(enc_uuid, key):
    """
        enc_uuid format is
        ciphertext+mac[0:11] || V4CONST || cipherext+mac[11:] || iv
    """
    enc_uuid = enc_uuid.replace('-','')
    ct_mac = enc_uuid[0:12] + enc_uuid[13:16]
    iv_bytes = bytes.fromhex(enc_uuid[16:])
    ct_bytes = bytes.fromhex(ct_mac[0:6])
    des_key = bytes.fromhex(key[0:48])
    mac_key = bytes.fromhex(key[48:])

    cipher = DES3.new(des_key, DES3.MODE_CFB, iv=iv_bytes)
    plaintext_bytes = cipher.decrypt(ct_bytes)

    mac = HMAC.new(mac_key, digestmod=SHA256).update(plaintext_bytes).hexdigest()

    if ct_mac[6:] != mac[0:9]:
        raise ValueError('Invalid MAC')

    return plaintext_bytes


def uuidv4(arg_value, pat=UUIDV4_PATTERN_LOOSE):
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

args = parser.parse_args()

if ENCRYPT_SUBPARSER == args.subparser:
    enc_uuid, composite_key = encrypt(args.data)

    print(f'Please save this composite encryption key:\n{composite_key}\n')
    print(f'UUIDv4: {enc_uuid}')
if DECRYPT_SUBPARSER == args.subparser:
    print(decrypt(args.uuidv4, args.key))
