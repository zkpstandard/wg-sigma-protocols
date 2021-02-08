# Sections ideas:

## Introduction
_Sigma protocols are simple, mature and powerful zero-knowledge proofs in privacy-preserving system_. Unfortunately, the implementation details are often times overlooked in acamic papers, and as a results a lot of insecure implementations have been proposed in the past.
-  leaking, reusing, leaking a few bits is fatal. Sony’s Playstation 3. The hacker group fail0verflow showed that Sony was reusing the same nonce for every digitally signed game. The members could then calculate the private key and create valid signatures for arbitrary files including pirated games or Linux applications. Console hacking 2010 – ps3 epic fail,” in 27th Chaos
-  Monero small subgroup attack in implementing ed25519 [1](https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html) + ed25519 has different behaviour for batch and compress form
- HELIOS online voting platform

### Scope

Standard Schnorr proof, equipped with and/or composition, focusing on prime order groups over elliptic-curves, either compact (challenge+response) or batchable (commitment+response). API, selection of curves, and hash functions that should be considered for the task.


## Background and motivation

There is already an RFC about non-interactive schnorr proofs, but the API is insufficient for modern use-cases of schnorr proofs in the industry.

- stable and old
- list of examples
- inspired other cryptographic primitives


## Implementation

### Implementations already available
- [SCAPI](https://scapi.readthedocs.io/en/latest/interactive_layer/sigma_protocols.html)
- [zkp](https://docs.rs/zkp/0.7.0/zkp/)
- [zksk](https://arxiv.org/abs/1911.02459)
- [Emmy](https://github.com/xlab-si/emmy)
- [YAZKC](https://www.ei.ruhr-uni-bochum.de/forschung/veroeffentlichungen/YAZKC/)


### Main features
  - deterministic nonce generation (first proposed in [1](https://groups.google.com/g/sci.crypt/c/SalLSLBBTe4/m/xtYNGDe6irIJ) [2](https://groups.google.com/g/sci.crypt/c/3g8DnnEkv5A/m/a26mLrwfjiMJ))
  - transcript object
  - hashing with the group generator + domain separator
  - add optional data (as a message) in the proof
  - check if points in the group
  -
### selection of suitable curves and size recommandation

  - The same parameters used for EC-DSA can be adopted here
  - BLS12-381
  - secp bitcoin curve
  - ristretto [[hdevalence-ristretto]]

### API

- two structs for the proof: batchable and compressed
- function prove, verify, simulate

[HR08]: <https://tools.ietf.org/html/rfc8235#ref-HR08>
[hdevalence-ristretto]: <https://datatracker.ietf.org/doc/draft-hdevalence-cfrg-ristretto/>