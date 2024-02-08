package enroll

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type encryptCircuit struct {
	Expectedc1 twistededwards.Point `gnark:",public"`
	Expectedc2 twistededwards.Point `gnark:",public"`
	PublicKey  twistededwards.Point `gnark:",public"`
	Balance    frontend.Variable    `gnark:",public"`
	TacSk      frontend.Variable
	//PrivateKey frontend.Variable
	Randomness frontend.Variable
}

func (circuit *encryptCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.TacSk, circuit.Balance)
	delta_0 := mimc.Sum()

	curve, err := twistededwards.NewEdCurve(api, ecct.BN254)
	if err != nil {
		return err
	}

	_g1, _ := twistededwards.GetCurveParams(ecct.BN254)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}

	plaintext := curve.ScalarMul(g1, delta_0)

	//c1=m+r*pk,c2=r*G
	rpk := curve.ScalarMul(circuit.PublicKey, circuit.Randomness)
	c1 := curve.Add(plaintext, rpk)
	_h, _ := twistededwards.GetCurveParams(ecct.BN254)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	c2 := curve.ScalarMul(h, circuit.Randomness)

	api.AssertIsEqual(c1.X, circuit.Expectedc1.X)
	api.AssertIsEqual(c2.X, circuit.Expectedc2.X)
	return nil
}

func Encrypt() {
	hashFunc := hash.MIMC_BN254

	var assignment encryptCircuit

	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	_tacSk, _ := rand.Int(rand.Reader, params.Order)
	assignment.TacSk = _tacSk

	modulus := ecc.BN254.ScalarField()
	var balance big.Int
	balance.Sub(modulus, big.NewInt(1))
	assignment.Balance = balance

	_data := _tacSk.Bytes()
	data := append(_data, balance.Bytes()...)
	mimc := hashFunc.New()
	mimc.Write(data)
	_delta_0 := mimc.Sum(nil)
	var delta_0 big.Int
	delta_0.SetBytes(_delta_0)

	var _g1 bn254.PointAffine
	_g1.X.SetBigInt(params.Base[0])
	_g1.Y.SetBigInt(params.Base[1])

	var _plaintext bn254.PointAffine
	_plaintext.ScalarMultiplication(&_g1, &delta_0)
	//plaintext:=twistededwards.Point{X:_plaintext.X,Y:_plaintext.Y}

	privatekey, _ := rand.Int(rand.Reader, params.Order)
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _publickey bn254.PointAffine
	_publickey.ScalarMultiplication(&_h, privatekey)
	publickey := twistededwards.Point{X: _publickey.X, Y: _publickey.Y}
	assignment.PublicKey = publickey

	//c1=m+r*pk,c2=r*G
	r, _ := rand.Int(rand.Reader, params.Order)
	assignment.Randomness = r

	var _c1 bn254.PointAffine
	_c1.ScalarMultiplication(&_publickey, r)
	var c1 bn254.PointAffine
	c1.Add(&_c1, &_plaintext)
	var c2 bn254.PointAffine
	c2.ScalarMultiplication(&_h, r)
	assignment.Expectedc1 = twistededwards.Point{X: c1.X, Y: c1.Y}
	assignment.Expectedc2 = twistededwards.Point{X: c2.X, Y: c2.Y}

	//decrypt
	var c2sk bn254.PointAffine
	c2sk.ScalarMultiplication(&c2, privatekey)
	var _c2sk bn254.PointAffine
	_c2sk.Neg(&c2sk)
	var _complain bn254.PointAffine
	_complain.Add(&c1, &_c2sk)
	fmt.Println(_complain.Equal(&_plaintext))

	var circuit encryptCircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
