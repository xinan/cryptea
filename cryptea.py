#!/usr/bin/env python3

from base64 import b64encode, b64decode
from ngram_score import quadgram_score
from itertools import repeat, zip_longest
from functools import reduce, partial
from gmpy2 import popcount
from operator import is_not


def hex_to_base64(str):
  return b64encode(bytes.fromhex(str)).decode()
  
def xor(a, b):
  return bytes([x ^ y for x, y in zip(a, b)])
  
def xor_byte(bs, b):
  return xor(bs, b * len(bs))
  
def solve_single_byte_xor(c):
  candidates = [xor_byte(c, bytes([b])) for b in range(256)]
  return max(map(lambda t: (quadgram_score(t), t), candidates))

def xor_repeating(bs, key):
  return xor(bs, key * -(-len(bs) // len(key)))
  
def hamming_distance(a, b):
  return sum(map(lambda x: popcount(x), xor_repeating(a, b))) if len(a) >= len(b) else hamming_distance(b, a)

def chop(bs, n):
  for i in range(0, len(bs), n):
    yield bs[i:i + n]

def solve_repeating_key_xor(c, min_key_length=2, max_key_length=40, num_key_lengths_to_try=3):
  edit_distance = []
  for key_length in range(min_key_length, max_key_length + 1):
    chunks = list(chop(c, key_length))
    normalized_edit_distance = hamming_distance(chunks[0], chunks[1]) / key_length
    edit_distance.append((normalized_edit_distance, key_length))
  for score, key_length in min(edit_distance)[:num_key_lengths_to_try]:
    transposed_chunks = [list(filter(partial(is_not, None), column)) for column in zip_longest(*chop(c, key_length))]
    