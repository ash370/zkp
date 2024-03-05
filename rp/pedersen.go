package rp

import (
	"crypto/rand"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// generate curve point
func GeneratePoint() bn254.G1Affine {
	//curve := ecct.BN254
	//params, _ := twistededwards.GetCurveParams(curve)

	//r, _ := rand.Int(rand.Reader, params.Order)
	r, _ := rand.Int(rand.Reader, fr.Modulus())
	//var base bn254.PointAffine
	//base.X.SetBigInt(params.Base[0])
	//base.Y.SetBigInt(params.Base[1])

	/* */
	//fmt.Println("r of gh:", r)

	var _point bn254.G1Affine
	_point.ScalarMultiplicationBase(r)

	/* */
	//fmt.Println(_point.IsOnCurve())

	return _point
}

// pedersen: P=v*G+r*H
func Commit(G bn254.G1Affine, H bn254.G1Affine, secret *big.Int, blinding *big.Int) bn254.G1Affine {
	var vg bn254.G1Affine
	vg.ScalarMultiplication(&G, secret)

	var rh bn254.G1Affine
	rh.ScalarMultiplication(&H, blinding)

	var res bn254.G1Affine
	res.Add(&vg, &rh)

	return res
}

// pedersen: commiting single number
func CommitSingle(G bn254.G1Affine, secret *big.Int) bn254.G1Affine {
	var commit bn254.G1Affine
	commit.ScalarMultiplication(&G, secret)
	return commit
}

// generate N curve point for commiting vector
func GenerateMultiPoint(n int64) []bn254.G1Affine {
	/* */
	//fmt.Println("generate multi point:")

	var points []bn254.G1Affine
	for i := n; i > 0; i-- {
		points = append(points, GeneratePoint())
	}
	return points
}

// pedersen: commiting single vector
func CommitSingleVector(G_vector []bn254.G1Affine, secret []*big.Int) bn254.G1Affine {
	var commit bn254.G1Affine

	commit = CommitSingle(G_vector[0], secret[0])
	for i := 1; i < len(G_vector); i++ {
		commitArray := CommitSingle(G_vector[i], secret[i])
		commit.Add(&commit, &commitArray)
	}
	return commit
}

// pedersen: commiting vectors
func CommitVectors(G_vector []bn254.G1Affine, H_vector []bn254.G1Affine, secret1 []*big.Int, secret2 []*big.Int) bn254.G1Affine {
	var commit bn254.G1Affine

	commit = Commit(G_vector[0], H_vector[0], secret1[0], secret2[0])
	for i := 1; i < len(G_vector); i++ {
		commitArray := Commit(G_vector[i], H_vector[i], secret1[i], secret2[i])
		commit.Add(&commit, &commitArray)
	}
	return commit
}

/* test */
/*func T_CommitVectors() {
	G_vector := GenerateMultiPoint(4)
	H_vector := GenerateMultiPoint(4)
	a_L, _ := Generate_a_L(big.NewInt(2), 4)
	a_R := Generate_a_R(a_L)

	commit := CommitVectors(G_vector, H_vector, a_L, a_R)

	fmt.Println(commit.IsOnCurve())

}*/
