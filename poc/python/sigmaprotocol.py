from util import *
import pickle

class SigmaProtocol:
    def prover_commit(self, witness):
        pass

    def prover_response(self, state, challenge):
        pass
      
    def label(self):
        pass
    
    def simulate_commitment(self, challenge, response):
        pass
    
    def simulate_response(self):
        pass
    
    def challenge(self, message: bytes, commitment) -> bytes:
        hm = hash_function()
        hm.update(message)
        hm = pad_to_blocklen(hm.digest())
        
        commitment_bytes = pad_to_blocklen(pickle.dumps(commitment))
        
        result = self.first_block_hash.copy()
        result.update(hm)
        result.update(commitment_bytes)
        return result.digest()
    
    '''
    Sigma Protocols often need to compute hashes that include information about 
    the kind of protocol being ran, regardless of the actual inputted parameters of the protocol.
    This function computes this initial hash: H
    '''
    def _get_first_block_hash(self, ctx: bytes):
        hctx = hash_function()
        hctx.update(ctx)
        hctx = hctx.digest()
        
        first_block_hash = hash_function()
        first_block_hash.update(pad_to_blocklen(HD + self.label() + hctx))
        return first_block_hash
    
    def verifier(self, commitment, challenge, response):
        pass        
    
    def batchable_proof(self, witness, message: bytes):
        pstate, commitment = self.prover_commit(witness)
        challenge = self.challenge(message, commitment)
        response = self.prover_response(pstate, challenge)
        return (pickle.dumps(commitment), pickle.dumps(response))
    
    def batchable_verify(self, proof, message: bytes):
        commitment_bytes, response_bytes = proof
        commitment = pickle.loads(commitment_bytes)
        response = pickle.loads(response_bytes)
        
        challenge = self.challenge(message, commitment)
        return self.verifier(commitment, challenge, response)
    
    def short_proof(self, witness, message: bytes):
        pstate, commitment = self.prover_commit(witness)
        challenge = self.challenge(message, commitment)
        response = self.prover_response(pstate, challenge)
        return (pickle.dumps(challenge), pickle.dumps(response))
    
    def short_verify(self, proof, message: bytes):
        challenge_bytes, response_bytes = proof
        challenge = pickle.loads(challenge_bytes)
        response = pickle.loads(response_bytes)
        
        commitment = self.simulate_commitment(challenge, response)
        challenge_prime = self.challenge(message, commitment)
        return challenge == challenge_prime

'''
`SigmaAndComposition` is used to prove knowledge of two independent witnesses. 
'''
class SigmaAndComposition(SigmaProtocol):
    # Left and right are both sigma protocols
    def __init__(self, left: SigmaProtocol, right: SigmaProtocol):
        self.left = left
        self.right = right
        
        self.first_block_hash = self._get_first_block_hash(b"")
        
    def prover_commit(self, witness):
        w0, w1 = witness 
        left_state, left_commitment = self.left.prover_commit(w0)
        right_state, right_commitment = self.right.prover_commit(w1)
        return (left_state, right_state), (left_commitment, right_commitment)
    
    def prover_response(self, state, challenge):
        left_state, right_state = state
        left_response = self.left.prover_response(left_state, challenge)
        right_response = self.right.prover_response(right_state, challenge)
        return (left_response, right_response)
        
    def label(self):
        label = hash_function()
        label.update(pad_to_blocklen(b"zkpstd/sigma/and-v0.0.1"))
        label.update(self.left.label())
        label.update(self.right.label())
        return label.digest()
    
    def simulate_commitment(self, challenge, response):
        left_response, right_response = response
        left_commitment = self.left.simulate_commitment(challenge, left_response)
        right_commitment = self.right.simulate_commitment(challenge, right_response)
        return (left_commitment, right_commitment)
    
    def simulate_response(self):
        return (self.left.simulate_response(), self.right.simulate_response())

    def verifier(self, commitment, challenge, response):
        left_commitment, right_commitment = commitment
        left_response, right_response = response
        return (self.left.verifier(left_commitment, challenge, left_response)) and \
        (self.right.verifier(right_commitment, challenge, right_response))