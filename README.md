# zk-barter

Zero knowledge proof that a key/credential is real, wired into an escrow so nobody has to go first and just trust the other person.

## Author

Rushidev Jain  -
Contact support: [email](rushidevjain@gmail.com) | [teleg](https://t.me/Uku_Jain)

## After Cloning this repo:

install requirments.txt
run setup.py
Install any Etherium IDE that can run Solidity. deploy both .abi on-chain. Now it is published. next
install the headerfiles of prover_sc.cpp ==> Compile prover_sc.cpp ==> run .exe

## The problem this is trying to solve

Say Alice's selling Bob a product key game key, software license, whatever. Normal problem with deals like this: Bob doesn't want to pay until he knows the key actually works, and Alice doesn't want to hand over the key until she's actually got the money. Somebody has to go first, and whoever does is just trusting the other side not to screw them.

Plain escrow (Bob pays into a contract, Alice reveals the key, contract releases the money) only fixes half of that. It stops Alice from taking the money without revealing *something* but it can't tell if what she reveals is real. She could reveal garbage and the contract has no way to catch it, because all it can check is "does this match what was promised," not "is this actually a working key."

The missing piece is a way for Alice to prove *before* Bob commits to paying   that the key is genuine, without showing him the actual key (because then he'd just take it and walk). That's the whole point of a zero knowledge proof: prove a statement is true without revealing the thing that makes it true.

## How this is trying to pull that off

Built with libsnark: R1CS constraints compiled down to a Groth16 proof (`r1cs_gg_ppzksnark`), over the `alt_bn128` curve same curve Ethereum's `ecAdd` / `ecMul` precompiles use, so a verifier contract on-chain stays cheap.

Roughly, the circuit is aiming to prove something like:

> "I know a key `K` and a signature from the vendor's known public key over `K`, the signature checks out, and this ciphertext `C` is `K` encrypted to the buyer's public key."

— without ever revealing `K` or the signature. Why each piece is in there:

- **EdDSA gadget** .. this is the actual "is it real" check. The vendor signs every key it issues; proving you hold a valid signature over the key (without showing the signature) is a much stronger guarantee than "this hashes to something on a list somewhere."
- **Poseidon gadget** .. a hash function designed to be cheap *inside* a circuit. SHA256 inside R1CS is brutally expensive in constraint count; Poseidon exists specifically to not be.
- **ElGamal gadget** .. proves the ciphertext handed to the buyer actually decrypts to the same key that just passed the signature check. This is what lets the key get delivered without ever putting it in the clear on a public chain, where anyone watching could grab it.
- **Groth16** .. small, cheap-to-verify proofs, but it needs a trusted setup ceremony per circuit. Worth knowing going in, not something to bolt on as an afterthought later.

(That's the intent behind the pieces that are `#include`d so far the actual constraint logic tying them together is still to be written.)

## Where this actually stands right now

Straight up: it doesn't build yet, and here's exactly why.

`prover_sc.cpp` currently includes:

```cpp
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/poseidon/poseidon_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/signature/eddsa_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/encryption/elgamal_gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
```

I checked the actual upstream `scipr-lab/libsnark` repo directly (cloned it, grepped the whole tree). The last three headers poseidon / eddsa / elgamal don't exist anywhere in it. `gadgetlib1/gadgets/hashes/` only ships `sha256` and `knapsack`. So step one is writing those three gadgets ourselves against `gadgetlib1`, or tracking down a fork that already has them. That's real cryptography-engineering work, not a missing package.

Separate issue, underneath that one: libsnark itself is old. `libff` (the math library it sits on) hasn't had a real commit since March 2020. I built it fresh on a clean, modern Ubuntu box just to check, and its *own* bundled self-test .. generate a proof, immediately try to verify it .. failed. Same result on both curve backends, both proof systems it ships, debug and release builds. There's also an open, never-fixed upstream issue of it segfaulting specifically under Cygwin, deep inside GMP. `tools/zksnark_cygwin_check.sh` builds real upstream libsnark and runs that self-test on whatever machine you point it at .. worth running before sinking more hours into gadget-writing, so you know the ground isn't already cracked before building on it.

Build environment right now is Windows 7 + Cygwin64, which adds its own friction on top (no WSL on Win7, so the usual "just build it in WSL" escape hatch isn't there).

## Layout

```
zk-barter/
├── prover_sc.cpp                  # circuit + prover .. won't compile yet, see above
├── tools/
│   └── zksnark_cygwin_check.sh    # checks the libsnark toolchain works at all, before you build on it.
|--- bin /
|     ----  abi , json , bin       # for the on-chain deploy process on ether's Remix IDE
└── README.md
```

(Add to this as it grows .. there's no on-chain verifier contract in here yet, see roadmap.)

## Roadmap

- [ ] Write or source the Poseidon / EdDSA / ElGamal gadgets
- [ ] Get a clean pass on the libsnark self-test, in the real build environment
- [ ] Wire up the actual circuit: signature check + commitment + encryption consistency
- [ ] Trusted setup ceremony for the circuit once it's finalized
- [ ] On-chain Groth16 verifier (Solidity, via the `alt_bn128` pairing precompile)
- [ ] Escrow contract: lock funds, verify proof, release on delivery
- [ ] Decide whether libsnark's worth the friction long-term, or whether `circom` (Poseidon + EdDSA already built in, actively maintained) is the less painful road

## Heads up

This deals with real money changing hands and cryptography that hasn't been audited. Treat it as a research/prototype repo not something to point at real funds until it's actually been reviewed by someone who isn't just the person who wrote it.

## License

pending disperancy..
