package enroll

import (
	"crypto/rand"
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

type accountWit struct {
	A twistededwards.Point
	B twistededwards.Point
}

type enrollCircuit struct {
	ExpectedAcc   accountWit           `gnark:",public"`
	PublicKey     twistededwards.Point `gnark:",public"`
	Balance       frontend.Variable    `gnark:",public"`
	Randomness    frontend.Variable
	ExpectedTacPk twistededwards.Point `gnark:",public"`
	TacSk         frontend.Variable
	Seq           frontend.Variable
}

func (circuit *enrollCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, ecct.BN254)
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	//TK=g2*tk
	_g2, _ := twistededwards.GetCurveParams(ecct.BN254)
	g2 := twistededwards.Point{X: _g2.Base[0], Y: _g2.Base[1]}

	tacpk := curve.ScalarMul(g2, circuit.TacSk)
	api.AssertIsEqual(tacpk.X, circuit.ExpectedTacPk.X)

	//delta0=mimc(tk,seq)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	_g1, _ := twistededwards.GetCurveParams(ecct.BN254)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}

	plaintext := curve.ScalarMul(g1, delta_0)

	//acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=0
	rpk := curve.ScalarMul(circuit.PublicKey, circuit.Randomness)
	c1 := curve.Add(plaintext, rpk)
	_h, _ := twistededwards.GetCurveParams(ecct.BN254)
	h := twistededwards.Point{X: _h.Base[0], Y: _h.Base[1]}
	c2 := curve.ScalarMul(h, circuit.Randomness)
	api.AssertIsEqual(c1.X, circuit.ExpectedAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedAcc.B.X)

	return nil
}

func Enroll() {
	curve := ecct.BN254
	params, _ := twistededwards.GetCurveParams(curve)
	hashFunc := hash.MIMC_BN254

	var assignment enrollCircuit
	_tacSk, _ := rand.Int(rand.Reader, params.Order)
	assignment.TacSk = _tacSk

	//TK=g2*tk
	var _g2 bn254.PointAffine
	_g2.X.SetBigInt(params.Base[0])
	_g2.Y.SetBigInt(params.Base[1])
	var _tacPk bn254.PointAffine
	_tacPk.ScalarMultiplication(&_g2, _tacSk)
	tacPk := twistededwards.Point{X: _tacPk.X, Y: _tacPk.Y}
	assignment.ExpectedTacPk = tacPk

	//delta0=mimc(tk,seq)
	modulus := ecc.BN254.ScalarField()
	var seq big.Int
	seq.Sub(modulus, big.NewInt(1))
	assignment.Seq = seq
	_data := _tacSk.Bytes()
	data := append(_data, seq.Bytes()...)
	mimc := hashFunc.New()
	mimc.Write(data)
	_delta_0 := mimc.Sum(nil)
	var delta_0 big.Int
	delta_0.SetBytes(_delta_0)

	//acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=0
	var balance big.Int
	balance.SetString("0", 10)
	assignment.Balance = balance
	var _g1 bn254.PointAffine
	_g1.X.SetBigInt(params.Base[0])
	_g1.Y.SetBigInt(params.Base[1])
	var _plaintext bn254.PointAffine
	_plaintext.ScalarMultiplication(&_g1, &delta_0)
	privatekey, _ := rand.Int(rand.Reader, params.Order)
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _publickey bn254.PointAffine
	_publickey.ScalarMultiplication(&_h, privatekey)
	publickey := twistededwards.Point{X: _publickey.X, Y: _publickey.Y}
	assignment.PublicKey = publickey
	r, _ := rand.Int(rand.Reader, params.Order)
	assignment.Randomness = r
	var _c1 bn254.PointAffine
	_c1.ScalarMultiplication(&_publickey, r)
	var c1 bn254.PointAffine
	c1.Add(&_c1, &_plaintext)
	var c2 bn254.PointAffine
	c2.ScalarMultiplication(&_h, r)
	acc := accountWit{
		twistededwards.Point{X: c1.X, Y: c1.Y},
		twistededwards.Point{X: c2.X, Y: c2.Y},
	}
	assignment.ExpectedAcc = acc

	var circuit enrollCircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
	//2780
	//*
}
