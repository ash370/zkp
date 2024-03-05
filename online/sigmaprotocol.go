package online

import (
	"crypto/rand"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type commitParams struct {
	r *big.Int
}
type commitExpMul struct {
	commit bn254.PointAffine
}
type commitExpMuladd struct {
	commit bn254.PointAffine
}
type commitEnc struct {
	commit transactionTX
}
type response struct {
	rp big.Int
}
type commitMent struct{}

func (c commitMent) ParamsGen(params *twistededwards.CurveParams) commitParams {
	r, _ := rand.Int(rand.Reader, params.Order)
	return commitParams{r: r}
}
func (c commitMent) Commitmul(params commitParams, g bn254.PointAffine) commitExpMul {
	r := params.r
	var commit bn254.PointAffine
	commit.ScalarMultiplication(&g, r)
	return commitExpMul{commit: commit}
}
func (c commitMent) Commitmuladd(params1 commitParams, params2 commitParams, g1 bn254.PointAffine, g2 bn254.PointAffine) commitExpMuladd {
	r1 := params1.r
	r2 := params2.r

	var commit bn254.PointAffine
	var tmp1 bn254.PointAffine
	tmp1.ScalarMultiplication(&g1, r1)
	var tmp2 bn254.PointAffine
	tmp2.ScalarMultiplication(&g2, r2)
	commit.Add(&tmp1, &tmp2)

	return commitExpMuladd{commit: commit}
}
func (c commitMent) CommitencValid(tb commitParams, tr commitParams, pk elPublickey, params *twistededwards.CurveParams, g bn254.PointAffine) commitEnc {
	var plain bn254.PointAffine
	plain.ScalarMultiplication(&g, tb.r)
	Cipher := pk.Encrypt(params, plain, tr.r)
	return commitEnc{commit: Cipher}
}
func (r response) Response(params commitParams, challenge big.Int, witness *big.Int) response {
	var _res big.Int
	_res.Mul(&challenge, witness)
	var res big.Int
	res.Add(params.r, &_res)
	return response{rp: res}
}
