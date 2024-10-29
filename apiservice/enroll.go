package apiservice

import (
	"Asyn_CBDC/backend/enroll"
	"fmt"

	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

var (
	params   *twistededwards.CurveParams
	hashFunc hash.Hash
)

func init() {
	params, _ = twistededwards.GetCurveParams(ecctedwards.BN254)
	hashFunc = hash.MIMC_BN254
}

func Enroll() {
	acc := enroll.NewEnroll().Init(params, hashFunc).Acc
	fmt.Println("Enroll success! Acc: ", acc)
}
