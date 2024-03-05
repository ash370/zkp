package online

import (
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type elPublickey struct {
	pk bn254.PointAffine
}

type transactionTX struct {
	A bn254.PointAffine
	B bn254.PointAffine
}

func (pk elPublickey) Encrypt(params *twistededwards.CurveParams, acc bn254.PointAffine, r *big.Int) transactionTX {
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _c1 bn254.PointAffine
	_c1.ScalarMultiplication(&pk.pk, r)
	var c1 bn254.PointAffine
	c1.Add(&_c1, &acc)
	var c2 bn254.PointAffine
	c2.ScalarMultiplication(&_h, r)
	result := transactionTX{
		c1,
		c2,
	}
	return result
}
