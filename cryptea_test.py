from cryptea import *
from base64 import b64decode
from secrets import choice
from functools import partial

assert(hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d') == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

assert(xor(bytes.fromhex('1c0111001f010100061a024b53535009181c'), bytes.fromhex('686974207468652062756c6c277320657965')) == bytes.fromhex('746865206b696420646f6e277420706c6179'))

assert(solve_single_byte_xor(bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))[2] == b"Cooking MC's like a pound of bacon")

with open('test_data/single_byte_xor.txt', 'r') as f:
  assert(max([solve_single_byte_xor(bytes.fromhex(l)) for l in f.read().splitlines()])[2] == b'Now that the party is jumping\n')

assert(xor_repeating(b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal", b'ICE').hex() == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')

with open('test_data/repeating_xor.txt', 'r') as f:
  assert(solve_repeating_key_xor(b64decode(f.read()))[1] == b'Terminator X: Bring the noise')

with open('test_data/aes_ecb.txt', 'r') as f:
  assert(aes_ecb_decrypt(b64decode(f.read()), b'YELLOW SUBMARINE').startswith(b"I'm back and I'm ringin' the bell"))

with open('test_data/detect_ecb.txt', 'r') as f:
  for line in f.read().splitlines():
    if is_probably_ecb(bytes.fromhex(line)):
      assert(line == 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a')

assert(pkcs7_pad(b'YELLOW SUBMARINE', bs=20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')

with open('test_data/cbc.txt', 'r') as f:
  key, iv = b'YELLOW SUBMARINE', b'\x00' * AES.block_size
  encrypted = b64decode(f.read())
  decrypted = aes_cbc_decrypt(encrypted, key, iv)
  re_encrypted = aes_cbc_encrypt(decrypted, key, iv, prepend_iv=False)
  assert(re_encrypted == encrypted)
  
for i in range(1024):
  mode = choice([AES.MODE_CBC, AES.MODE_ECB])
  assert(detect_ebc_or_cbc(partial(ebc_cbc_oracle, mode)) == mode)
