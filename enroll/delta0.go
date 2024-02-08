package enroll

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type deltaCircuit struct {
	Expected frontend.Variable `gnark:",public"`
	Balance  frontend.Variable `gnark:",public"`
	TacSk    frontend.Variable
}

func (circuit *deltaCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.TacSk, circuit.Balance)
	delta_0 := mimc.Sum()

	api.AssertIsEqual(delta_0, circuit.Expected)

	return nil
}

func Comptdelta() {
	hashFunc := hash.MIMC_BN254

	var assignment deltaCircuit

	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	tacSk, _ := rand.Int(rand.Reader, params.Order)
	assignment.TacSk = tacSk

	modulus := ecc.BN254.ScalarField()
	var balance big.Int
	balance.Sub(modulus, big.NewInt(1))

	assignment.Balance = balance //这里不传大整数会报错，生成witness的时候数据传不进去，报错访问空指针

	_data := tacSk.Bytes()
	data := append(_data, balance.Bytes()...)

	mimc := hashFunc.New()
	mimc.Write(data)
	delta_0 := mimc.Sum(nil)

	assignment.Expected = delta_0

	var circuit deltaCircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	fmt.Println(witness)
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
