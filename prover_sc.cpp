

// prover.cpp                Alice's ZK SNARK proof generator the ZPiK
//
// Library:
//       libsnark R1CS + Groth16, gadget composition style.
//  standard libsnark gadget API surface
//   would only reflects how a production circuit is actually assembled protoboard,
// pb_variable allocation, gadget wiring & then witness generation +proving
//
// Circuit being proven all in 1 R1CS constraint system
//      commitment      == Poseidon(key) #
//    issuer's signature is a valid EdDSA signature over key under issuer's pk
//  ciphertext       == El Gamal encrypt(bob_pk, key, randomness (PRNGs LCGs   maybe))
//
// Public inputs:  commitment, issuer_pk, bob_pk, ciphertext
// Private witness: key, issuer_signature, encryption randomness

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/poseidon/poseidon_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/signature/eddsa_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/encryption/elgamal_gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>      
//i don't have .Cmake file plz use vcpkg

using namespace libsnark;
using namespace libff;

typedef alt_bn128_pp ppT;      //BN254  matches Solidity of Juan Blanco compiler for 
//pairing checks also alt_bn128 part is declaired here
typedef Fr<ppT> FieldT;


//Key exchange circuit: wires the three gadget into a single constraint system

class KeyExchangeCircuit {
public:
    protoboard<FieldT> pb;

    //Public input wires
    pb_variable<FieldT> commitment;
    pb_variable_array<FieldT> issuer_pk;
    pb_variable_array<FieldT> bob_pk;
    pb_variable_array<FieldT> ciphertext;

    // Private witness wires
    pb_variable_array<FieldT> key_bits;       // the secret product key    bit decomposed
    pb_variable_array<FieldT> signature;      // EdDSA(issuer   sk, the key)
    pb_variable_array<FieldT> enc_randomness; // El Gamal encryption randomness (URV)   inverse transformation method for gen. - Roman Paolucci
    //Sub gadgets
    std::shared_ptr<poseidon_gadget<FieldT>>            hash_gadget;
    std::shared_ptr<eddsa_signature_verify_gadget<FieldT>> sig_gadget;
    std::shared_ptr<elgamal_encrypt_gadget<FieldT>>      enc_gadget;

    KeyExchangeCircuit() {
        //allocate public inputs first order matters must match
        //     the order the Solidity verifier expects
        commitment.allocate(pb, "commitment");
        issuer_pk.allocate(pb, 2, "issuer_pk");     // (x, y) on Baby Jubjub
        bob_pk.allocate(pb, 2, "bob_pk");
        ciphertext.allocate(pb, 2, "ciphertext");   // El Gamal (c1, c2)

        pb.set_input_sizes(1 + 2 + 2 + 2); // commitment + issuer_pk + bob_pk + ciphertext

        //  allocate private witness
        key_bits.allocate(pb, 256, "key_bits");
        signature.allocate(pb, 2, "signature");     // (R, s)
        enc_randomness.allocate(pb, 1, "enc_randomness");

        // 1] Poseidon(key) ==commitment
        hash_gadget.reset(new poseidon_gadget<FieldT>(
            pb,key_bits,  commitment, "poseidon(key)==commitment"));

        //2] EdDSA_Verify(issuer_pk,key, signature)==true
        sig_gadget.reset(new eddsa_signature_verify_gadget<FieldT>(
            pb, issuer_pk,  key_bits,signature, "verify issuer signature"));

        //3 El Gamal_Encrypt(bob_pk,key,r) ==cipher text
        enc_gadget.reset(new elgamal_encrypt_gadget<FieldT>(
            pb, bob_pk, key_bits,enc_randomness, ciphertext,
            "verify ciphertext encrypts key"));
    }

    void generate_r1cs_constraints() {
        hash_gadget->generate_r1cs_constraints();
        sig_gadget->generate_r1cs_constraints();
        enc_gadget->generate_r1cs_constraints();
    }

    //Fills in the witness the actual secret values and runs each gadget's
    //witnessgeneration so every constraint has a satisfying assignments
    void generate_r1cs_witness(const std::vector<bool>& key,
                                const std::pair<FieldT, FieldT>& sig,
                                const FieldT& randomness) {
        key_bits.fill_with_bits(pb, key);
        signature.fill_with_field_elements(pb, {sig.first, sig.second});
        enc_randomness.fill_with_field_elements(pb, {randomness});

        hash_gadget->generate_r1cs_witness();
        sig_gadget->generate_r1cs_witness();
        enc_gadget->generate_r1cs_witness();
    }
};


// _main: build circuit ==> (1 time) trusted setup ==> prove ==> export for Solidity
int main() {
    ppT::init_public_params();

    KeyExchangeCircuit circuit;
    circuit.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> cs = circuit.pb.get_constraint_system();

    //Important Concept :in production this keypair comes from a 1 time multi party
    // trusted setup ceremony run by the marketplace operator + independent
    // auditors and NOT regenerated per trade.. Loaded from disk here
    r1cs_gg_ppzksnark_keypair<ppT> keypair =
        r1cs_gg_ppzksnark_generator<ppT>(cs);

    
    std::vector<bool> alice_key_bits= load_key_as_bits("alice_product_key.bin");
    std::pair<FieldT, FieldT> issuer_sig = load_issuer_signature("issuer_sig.bin");
    FieldT enc_randomness= FieldT::random_element();//Alice supplies her real secret data here

    circuit.generate_r1cs_witness(alice_key_bits, issuer_sig, enc_randomness);

    //fallback
    if (!circuit.pb.is_satisfied()) {
        throw std::runtime_error("Witness does not satisfy circuit invalid key, "
                                  "bad issuer signature, or ciphertext mismatch.");
    }

    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(
        keypair.pk, circuit.pb.primary_input(), circuit.pb.auxiliary_input());

    //Export proof + public inputs as Solidity ABI compatible calldata
    // (uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[7] publicInputs)
    export_proof_as_solidity_calldata(proof, circuit.pb.primary_input(),
                                       "proof_calldata.json");

    std::cout << "Proof generated. Alice can now call Escrow.settle(proof) on chain.\n";
    return 0;
}
