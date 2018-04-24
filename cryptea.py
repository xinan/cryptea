#!/usr/bin/env python3

from base64 import b64encode, b64decode
from ngram_score import quadgram_score, monogram_score
from itertools import repeat, zip_longest, combinations, starmap
from functools import reduce, partial
from gmpy2 import popcount
from operator import is_not
from heapq import nsmallest
from statistics import mean
from Crypto.Cipher import AES
from collections import deque
from secrets import token_bytes, choice


def hex_to_base64(str):
  return b64encode(bytes.fromhex(str)).decode()
  
def xor(a, b):
  return bytes([x ^ y for x, y in zip(a, b)])
  
def xor_byte(bs, b):
  return xor(bs, b * len(bs))
  
def solve_single_byte_xor(c, scorer=quadgram_score):
  '''Returns (score, key, text)'''
  candidates = [(b, xor_byte(c, bytes([b]))) for b in range(256)]
  return max(starmap(lambda k, d: (scorer(d), k, d), candidates))

def xor_repeating(bs, key):
  return xor(bs, key * -(-len(bs) // len(key)))
  
def hamming_distance(a, b):
  return sum(map(lambda x: popcount(x), xor(a, b))) if len(a) >= len(b) else hamming_distance(b, a)

def chop(bs, n):
  for i in range(0, len(bs), n):
    yield bs[i:i + n]

def transpose(matrix):
  return [list(filter(partial(is_not, None), column)) for column in zip_longest(*matrix)]

def solve_repeating_key_xor(c, min_key_length=2, max_key_length=40, num_key_lengths_to_try=3):
  '''Returns (score, key, text)'''
  max_key_length = min(max_key_length, len(c) // 2)               
  edit_distances = []
  for key_length in range(min_key_length, max_key_length + 1):
    chunks = list(chop(c, key_length))
    normalized_edit_distance = mean(map(lambda p: hamming_distance(*p) / key_length, combinations(chunks[:4], 2)))
    edit_distances.append((normalized_edit_distance, key_length))
  candidates = []
  for _, key_length in nsmallest(num_key_lengths_to_try, edit_distances):
    _, keys, decrypted_columns = zip(*map(lambda c: solve_single_byte_xor(c, scorer=monogram_score), map(bytes, transpose(chop(c, key_length)))))
    decrypted_key = bytes(keys)
    decrypted_text = b''.join(map(bytes, transpose(decrypted_columns)))
    candidates.append((decrypted_key, decrypted_text))
  return max(starmap(lambda k, d: (quadgram_score(d), k, d), candidates))
  
def aes_ecb_encrypt(m, key):
  aes = AES.new(key, AES.MODE_ECB)
  return aes.encrypt(m)

def aes_ecb_decrypt(c, key):
  aes = AES.new(key, AES.MODE_ECB)
  return aes.decrypt(c)

def is_probably_ecb(c):
  return len(set(chop(c, AES.block_size))) < len(c) / AES.block_size

def pkcs7_pad(s, bs=AES.block_size):
  return s + (bs - len(s) % bs) * bytes([bs - len(s) % bs])
  
def pkcs7_unpad(s):
  return s[0:-s[-1]]
  
def aes_cbc_encrypt(m, key, iv, prepend_iv=True):
  plaintext_blocks = chop(pkcs7_pad(m), AES.block_size)
  ciphertext_blocks = deque([iv])
  for blk in plaintext_blocks:
    ciphertext_blocks.append(aes_ecb_encrypt(xor(blk, ciphertext_blocks[-1]), key))
  if not prepend_iv:
    ciphertext_blocks.popleft()
  return b''.join(ciphertext_blocks)

def aes_cbc_decrypt(c, key, iv=None):
  ciphertext_blocks = deque(chop(c, AES.block_size))
  if iv:
    ciphertext_blocks.insert(0, iv)
  plaintext_blocks = []
  for i in range(1, len(ciphertext_blocks)):
    plaintext_blocks.append(xor(aes_ecb_decrypt(ciphertext_blocks[i], key), ciphertext_blocks[i - 1]))
  return pkcs7_unpad(b''.join(plaintext_blocks))
  
def ebc_cbc_oracle(mode, m):
  key = token_bytes(AES.block_size)
  m = token_bytes(choice(range(5, 11))) + m + token_bytes(choice(range(5, 11)))
  if mode == AES.MODE_CBC:
    iv = token_bytes(AES.block_size)
    return aes_cbc_encrypt(m, key, iv, prepend_iv=False)
  elif mode == AES.MODE_ECB:
    return aes_ecb_encrypt(pkcs7_pad(m), key)
  else:
    raise ValueError
    
def detect_ebc_or_cbc(oracle):
  payload = b'\x00' * AES.block_size * 3
  encrypted = oracle(payload)
  blocks = list(chop(encrypted, AES.block_size))
  if blocks[1] == blocks[2]:
    return AES.MODE_ECB
  else:
    return AES.MODE_CBC