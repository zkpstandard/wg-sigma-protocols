from hashlib import sha3_256 as hash_function
from secrets import token_bytes as random_bytes
from sage.all import *

# Define some constants used for hashing unique values.

DOMSEP = b"zkpstd/sigma/0.1"

HD = hash_function()

BLOCK_LEN = HD.block_size
DIGEST_LEN = HD.digest_size

HD.update(DOMSEP)
HD = HD.digest() 

def pad_to_blocklen(s: bytes) -> bytes: 
    '''
    Pads bytestring `s` with 0's, so that its length is a multiple of `BLOCK_LEN`
    '''
    padding = b"\000" * (BLOCK_LEN - (len(s) % BLOCK_LEN))
    return s + padding

def hash_to_seed(b: bytes) -> int:
    '''
    Turns a hash digest (bytestring) into an int, which can be used to seed the sage PRNG
    '''
    return int.from_bytes(b, "big")

def hash_algebraic(x) -> bytes:
    '''
    Hashes a sage object into bytes
    '''
    return hash(x).to_bytes(8, "big", signed=True)

from collections import namedtuple
# Define the elliptic curve secp256k1

Zq = GF(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f)
E = EllipticCurve(Zq, [0, 7])
G = E.lift_x(Integer(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))
H = E.lift_x(Integer(0xc9e777de60dff3bb651b89183754bbc633c34b124429afe8cbaff130abb7bff5))
p = G.order()
Zp = GF(p)

EC = namedtuple('EC', ['G', 'H', 'E', 'p', 'Fp'])
secp256k1 = EC(G, H, E, p, Zp)

secp256k1_bytes = bytearray()
for i in secp256k1:
    secp256k1_bytes.extend(hash_algebraic(i))
