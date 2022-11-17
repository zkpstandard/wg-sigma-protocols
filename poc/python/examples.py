from util import random_bytes
from discretelog import SchnorrDlog, DlogEQ
from sigmaprotocol import SigmaAndComposition
from sage.all import *

if __name__ == "__main__":
    sk0 = [SchnorrDlog.ec.Fp.random_element()]
    pk0 = [SchnorrDlog.ec.G * Integer(sk0[0])]
    schnorr0 = SchnorrDlog(b"context", pk0)

    print(f"Schnorr signature for secret key:\n{sk0}\n\npublic key:\n{pk0}")
    batch_proof = schnorr0.batchable_proof(sk0, b"I'm signing this message")
    if schnorr0.batchable_verify(batch_proof, b"I'm signing this message"):
        print("Signature verified")
    else: 
        print("Signature not verified")

    print("\n===================================\n")
    sk1 = [SchnorrDlog.ec.Fp.random_element()]
    pk1 = [SchnorrDlog.ec.G * Integer(sk1[0])]
    schnorr1 = SchnorrDlog(b"context", pk1)

    print(f"SigmaAndComposition for witness:\{(sk0, sk1)}\n\nstatement:\n{(pk0, pk1)}")
    schnorrAnd = SigmaAndComposition(schnorr0, schnorr1)
    and_proof = schnorrAnd.short_proof((sk0, sk1), b"message")
    if schnorrAnd.short_verify(and_proof, b"message"):
        print("And composition verified")
    else:
        print("And composition not verified")

    print("\n===================================\n")
    
    witness = [DlogEQ.ec.Fp.random_element()]
    statement = [DlogEQ.ec.G * Integer(witness[0]), DlogEQ.ec.H * Integer(witness[0])]
    dleq = DlogEQ(b"ctx", statement)

    print(f"Discrete Log Equality for witness:\n{witness}\n\nstatement:\n{statement}")
    dleq_proof = dleq.short_proof(witness, b"message")
    if dleq.short_verify(dleq_proof, b"message"):
        print("Discrete Log Equality verified")
    else:
        print("Discrete Log Equality not verified")
    


