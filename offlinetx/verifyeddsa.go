package offlinetx

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	cir_eddsa "github.com/consensys/gnark/std/signature/eddsa"
)

type eddsaCircuit struct {
	PublicKey cir_eddsa.PublicKey `gnark:",public"`
	Signature cir_eddsa.Signature
	Message   frontend.Variable
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, ecct.BN254)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return cir_eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)

	return nil
}

func VerifyEddsa() {
	var _c1, _c2 fr.Element
	_c1.SetRandom()
	_c2.SetRandom()
	c1 := _c1.Bytes()
	c2 := _c2.Bytes()
	var _msg []byte
	_msg = append(_msg, c1[:]...)
	var msg []byte
	msg = append(msg, c2[:]...)

	hFunc := hash.MIMC_BN254.New()

	privateKey, _ := eddsa.New(ecct.BN254, rand.Reader)

	publicKey := privateKey.Public()

	signature, _ := privateKey.Sign(msg, hFunc)
	fmt.Println(signature)

	isValid, _ := publicKey.Verify(signature, msg, hFunc)
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}

	var circuit eddsaCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// generating pk, vk
	pk, vk, err := groth16.Setup(r1cs)

	// declare the witness
	var assignment eddsaCircuit

	// assign message value
	assignment.Message = msg

	// public key bytes
	_publicKey := publicKey.Bytes()

	// assign public key values
	assignment.PublicKey.Assign(ecct.BN254, _publicKey[:32])

	// assign signature values
	assignment.Signature.Assign(ecct.BN254, signature)

	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	// generate the proof
	proof, err := groth16.Prove(r1cs, pk, witness)

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
