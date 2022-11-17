from util import *
from sigmaprotocol import *

class DlogTemplate(SigmaProtocol):
    # n is the input dimension of the homomorphism
    # m is the output dimension of the homomorphism
    n = None
    m = None
    
    # ec specifies the elliptic curve used
    # defaults to secp256k1
    ec = secp256k1
    
    def __init__(self, ctx: bytes, statement):
        assert(len(statement) == self.n)
        self.statement = statement
        self.first_block_hash = self._get_first_block_hash(ctx)
        
    def prover_commit(self, witness):
        assert(len(witness) == self.m)
        
        # First, seed rng
        witness_bytes = pickle.dumps(witness)
        second_block = pad_to_blocklen(random_bytes(32) + witness_bytes)
        h = self.first_block_hash.copy()
        h.update(second_block)
        commit_seed = hash_to_seed(h.digest())
        with seed(commit_seed):
            # nonce is an n-length array of Fp elements
            nonce = [self.ec.Fp.random_element() for _ in range(self.n)]
            # commitment is an m-length array of G2 elements
            commitment = self._morphism(nonce)
            prover_state = (witness, nonce)
            return (prover_state, commitment)
    
    # Prover_state is nonce (array of n Fp elements) * witness (array of n Fp elements)
    # challenge is bytes, but is converted to an Fp element
    # outputs an array of n Fp elements
    def prover_response(self, prover_state, challenge: bytes):
        witness, nonce = prover_state
        challenge = self._chal_from_bytes(challenge)
        return [challenge * witness_i + nonce_i 
                for (witness_i, nonce_i) in zip(witness, nonce)]
    
    def simulate_response(self):
        return [self.ec.Fp.random_element() 
                for _ in range(self.m)]
    
    def simulate_commitment(self, challenge: bytes, response):
        challenge = self._chal_from_bytes(challenge)
        morphism_of_response = self._morphism(response)
        return [phi_i - statement_i * Integer(challenge) 
                for (phi_i, statement_i) 
                in zip(morphism_of_response, self.statement)]

    def _morphism(self, x):
        raise NotImplementedError
        
    def _morphism_label(self):
        raise NotImplementedError
    
    def label(self):
        return self._morphism_label()
    
    def verifier(self, commitment, challenge: bytes, response):
        challenge = self._chal_from_bytes(challenge)
        return all(phi_response_i == commitment_i + statement_i * int(challenge)
            for phi_response_i, commitment_i, statement_i in zip(self._morphism(response), commitment, self.statement))
    
    def _chal_from_bytes(self, challenge: bytes) -> ec.Fp:
        with seed(hash_to_seed(challenge)):
            return self.ec.Fp.random_element()

class SchnorrDlog(DlogTemplate):
    n = 1
    m = 1
    ec = secp256k1
    first_hash_label = hash_function()
    first_hash_label.update(b"schnorr" + pickle.dumps(ec))
    
    # Inputs an array of one Fp element `x`
    # Outputs `[G * x]`
    
    def _morphism(self, x):
        return [self.ec.G * int(x[0])]
    
    def _morphism_label(self):
        label = self.first_hash_label.copy()
        label.update(pickle.dumps(self.ec.G))
        label.update(pickle.dumps(self.statement[0]))
        return label.digest()

class DlogEQ(DlogTemplate):
    ec = secp256k1
    n = 2
    m = 1
    
    # Inputs an array of one Fp element `x`
    # Outputs `[G * x, H * x]`
    def _morphism(self, x):
        return [self.ec.G * int(x[0]), self.ec.H * int(x[0])]
    
    def _morphism_label(self):
        label = hash_function()
        label.update(b"dleq")
        label.update(pickle.dumps(self.ec.G))
        label.update(pickle.dumps(self.ec.H))
        label.update(pickle.dumps(self.statement[0]))
        label.update(pickle.dumps(self.statement[1]))
        return label.digest()