from util import *
from sigmaprotocol import *

class DlogTemplate(SigmaProtocol):
    '''
    n is the input dimension of the homomorphism (size of witness)
    m is the output dimension of the homomorphism (size of statement)
    ec specifies the elliptic curve used. Defaults to secp256k1. 
    '''
    n = None
    m = None
    ec = secp256k1
    
    def __init__(self, ctx: bytes, statement):
        '''
        Initialize a sigma protocol for discrete log applications. 
        statement is an array of m field elements. 
        '''
        assert(len(statement) == self.m)
        self.statement = statement
        self.first_block_hash = self._get_first_block_hash(ctx)
        
    def _prover_commit(self, witness):
        '''
        Outputs a prover_state and a commitment. 
        The prover state will later be used to generate a challenge response. 
        The verifier will later use the commitment to verify the challenge response.

        witness is an array of n Fp elements. 
        '''
        assert(len(witness) == self.n)
        
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
    
    def _prover_response(self, prover_state, challenge: bytes):
        '''
        Prover_state is nonce (array of n Fp elements) , witness (array of n Fp elements)
        challenge is bytes, but is converted to an Fp element
        outputs an array of n Fp elements
        '''
        witness, nonce = prover_state
        challenge = self._chal_from_bytes(challenge)
        return [challenge * witness_i + nonce_i 
                for (witness_i, nonce_i) in zip(witness, nonce)]
    
    def _simulate_response(self):
        '''
        Simulates a random prover_response. 
        For this application, it's a uniformly random array of m Fp elements. 
        '''
        return [self.ec.Fp.random_element() 
                for _ in range(self.m)]
    
    def _simulate_commitment(self, challenge: bytes, response):
        '''
        Simulates a random prover commitment, given a certain challenge and response. 
        '''
        challenge = self._chal_from_bytes(challenge)
        morphism_of_response = self._morphism(response)
        return [phi_i - statement_i * Integer(challenge) 
                for (phi_i, statement_i) 
                in zip(morphism_of_response, self.statement)]

    def _morphism(self, x):
        raise NotImplementedError
        
    def _morphism_label(self):
        raise NotImplementedError
    
    def _label(self):
        return self._morphism_label()
    
    def _verifier(self, commitment, challenge: bytes, response):
        challenge = self._chal_from_bytes(challenge)
        return all(phi_response_i == commitment_i + statement_i * Integer(challenge)
            for phi_response_i, commitment_i, statement_i in zip(self._morphism(response), commitment, self.statement))
    
    def _chal_from_bytes(self, challenge: bytes) -> ec.Fp:
        with seed(hash_to_seed(challenge)):
            return self.ec.Fp.random_element()

class SchnorrDlog(DlogTemplate):
    n = 1
    m = 1
    ec = secp256k1
    first_hash_label = hash_function()
    first_hash_label.update(pad_to_blocklen(b"schnorr" + pickle.dumps(ec)))
    
    def _morphism(self, x):
        '''
        Inputs an array of one Fp element `x`
        Outputs `[G * x]`
        '''
        return [self.ec.G * Integer(x[0])]
    
    def _morphism_label(self):
        label = SchnorrDlog.first_hash_label.copy()
        label.update(pickle.dumps(self.ec.G))
        label.update(pickle.dumps(self.statement[0]))
        return label.digest()

class DlogEQ(DlogTemplate):
    ec = secp256k1
    n = 1
    m = 2
    first_hash_label = hash_function()
    first_hash_label.update(pad_to_blocklen(b"dleq" + pickle.dumps(ec)))

    def _morphism(self, x):
        '''
        Inputs an array of one Fp element `x`
        Outputs `[G * x, H * x]`
        '''
        return [self.ec.G * Integer(x[0]), self.ec.H * Integer(x[0])]
    
    def _morphism_label(self):
        label = DlogEQ.first_hash_label.copy()
        label.update(pickle.dumps(self.ec.G))
        label.update(pickle.dumps(self.ec.H))
        label.update(pickle.dumps(self.statement[0]))
        label.update(pickle.dumps(self.statement[1]))
        return label.digest()

class DiffieHelman(DlogTemplate):
    ec = secp256k1
    n = 2
    m = 3
    first_hash_label = hash_function()
    first_hash_label.update(pad_to_blocklen(b"diffiehelman" + pickle.dumps(ec)))
    
    def _morphism(self, x):
        '''
        Inputs an array of two Fp elements `x0`, `x1`
        Outputs `[G * x0, G * x1, G * Y0 * x1]`, where `Y0` is `G * x0` from the statement. 
        '''
        return [self.ec.G * Integer(x[0]), self.ec.G * Integer(x[1]), self.statement[0] * Integer(x[1])]
    
    def _morphism_label(self):
        label = DiffieHelman.first_hash_label.copy()
        label.update(pickle.dumps(self.ec.G))
        label.update(pickle.dumps(self.statement[0]))
        label.update(pickle.dumps(self.statement[1]))
        return label.digest()