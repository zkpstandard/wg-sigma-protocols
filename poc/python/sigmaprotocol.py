from util import *
import pickle

class SigmaProtocol:
    com = ""
    message = ""

    

    def _prover_commit(self, witness):
        pass

    def _prover_response(self, state, challenge):
        pass
      
    def _label(self):
        pass
    
    def _simulate_commitment(self, challenge, response):
        pass
    
    def _simulate_response(self):
        pass
    
    def _commitment_to_bytes(self, commitment) -> bytes:
        '''
        Deterministically converts a commitment to bytes.
        Use this for hashing, not serialization. 
        '''
        pass

    def _challenge(self, message: bytes, commitment) -> bytes:
        '''
        Deterministically computes a challenge given a message and commitment. 
        Used in Fiat-shamir transform. 
        '''
        hm = hash_function()
        hm.update(message)
        hm_bytes = pad_to_blocklen(hm.digest())
        
        commitment_bytes = pad_to_blocklen(self._commitment_to_bytes(commitment))
        result = self.first_block_hash.copy()
        result.update(hm_bytes)
        result.update(commitment_bytes)
        return result.digest()
    
    def _get_first_block_hash(self, ctx: bytes):
        '''
        Sigma Protocols often need to compute hashes that include information about 
        the kind of protocol being ran, regardless of the actual inputted parameters of the protocol.
        This function computes this initial hash.
        '''
        hctx = hash_function()
        hctx.update(ctx)
        hctx = hctx.digest()
        
        first_block_hash = hash_function()
        first_block_hash.update(pad_to_blocklen(HD + self._label() + hctx))
        return first_block_hash
    
    def _verifier(self, commitment, challenge, response):
        pass        
    
    def batchable_proof(self, witness, message: bytes):
        '''
        Verify a batchable proof in a non-interactive way. 
        This is the canonical form for Sigma Protocol proofs. 

        WARNING: this needs to validate that the commitment / response are correctly formatted. 
        Failure to do so could lead to security vulnerabilities. See spec for more details.
        '''
        pstate, commitment = self._prover_commit(witness)
        challenge = self._challenge(message, commitment)
        response = self._prover_response(pstate, challenge)
        return (pickle.dumps(commitment), pickle.dumps(response))
    
    def batchable_verify(self, proof, message: bytes):
        '''
        Verify a batchable proof in a non-interactive way. 
        This is the canonical form for Sigma Protocol proofs. 

        WARNING: this needs to validate that the commitment / response are correctly formatted. 
        Failure to do so could lead to security vulnerabilities. See spec for more details.
        '''
        commitment_bytes, response_bytes = proof
        commitment = pickle.loads(commitment_bytes)
        response = pickle.loads(response_bytes)
        
        challenge = self._challenge(message, commitment)
        return self._verifier(commitment, challenge, response)
    
    def short_proof(self, witness, message: bytes):
        '''
        Generate a short proof in a non-interactive way. 
        If the commitment is very large, this form is preferred. Eg. an AND composition. 

        WARNING: This construction only works when the commitment `T` is UNIQUELY determined by challenge `c` and response `s`. 
        '''
        pstate, commitment = self._prover_commit(witness)
        challenge = self._challenge(message, commitment)
        response = self._prover_response(pstate, challenge)
        return (pickle.dumps(challenge), pickle.dumps(response))
    
    def short_verify(self, proof, message: bytes):
        '''
        Generate a short proof in a non-interactive way. 
        If the commitment is very large, this form is preferred. Eg. an AND composition. 

        WARNING: This construction only works when the commitment `T` is UNIQUELY determined by challenge `c` and response `s`. 
        '''
        challenge_bytes, response_bytes = proof
        challenge = pickle.loads(challenge_bytes)
        response = pickle.loads(response_bytes)
        
        commitment = self._simulate_commitment(challenge, response)
        challenge_prime = self._challenge(message, commitment)
        return challenge == challenge_prime

class SigmaAndComposition(SigmaProtocol):
    '''
    `SigmaAndComposition` is used to prove knowledge of two independent witnesses. 
    '''
    def __init__(self, left: SigmaProtocol, right: SigmaProtocol):
        self.left = left
        self.right = right
        
        self.first_block_hash = self._get_first_block_hash(b"")
        
    def _prover_commit(self, witness):
        w0, w1 = witness 
        left_state, left_commitment = self.left._prover_commit(w0)
        right_state, right_commitment = self.right._prover_commit(w1)
        return (left_state, right_state), (left_commitment, right_commitment)
    
    def _prover_response(self, state, challenge):
        left_state, right_state = state
        left_response = self.left._prover_response(left_state, challenge)
        right_response = self.right._prover_response(right_state, challenge)
        return (left_response, right_response)
        
    def _label(self):
        label = hash_function()
        label.update(pad_to_blocklen(b"zkpstd/sigma/and-v0.0.1"))
        label.update(self.left._label())
        label.update(self.right._label())
        return label.digest()
    
    def _simulate_commitment(self, challenge, response):
        left_response, right_response = response
        left_commitment = self.left._simulate_commitment(challenge, left_response)
        right_commitment = self.right._simulate_commitment(challenge, right_response)
        return (left_commitment, right_commitment)
    
    def _simulate_response(self):
        return (self.left._simulate_response(), self.right._simulate_response())

    def _verifier(self, commitment, challenge, response):
        left_commitment, right_commitment = commitment
        left_response, right_response = response
        return (self.left._verifier(left_commitment, challenge, left_response)) and \
        (self.right._verifier(right_commitment, challenge, right_response))

    def _commitment_to_bytes(self, commitment) -> bytes:
        left_commitment, right_commitment = commitment
        return self.left._commitment_to_bytes(left_commitment) \
            + self.right._commitment_to_bytes(right_commitment)