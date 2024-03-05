package rp

import (
	"crypto/rand"
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func BulletProof() {
	P := fr.Modulus()
	v := new(big.Int).SetInt64(130)
	n := int64(32)

	G := GenerateMultiPoint(n)
	H := GenerateMultiPoint(n)
	g := GeneratePoint()
	h := GeneratePoint()

	//gamma, _ := rand.Int(rand.Reader, params.Order)
	gamma, _ := rand.Int(rand.Reader, P)
	/* */
	//fmt.Println("gamma:", gamma)

	commitV := Commit(g, h, v, gamma)

	//generate commitA
	alpha, _ := rand.Int(rand.Reader, P)
	/* */
	//fmt.Println("alpha:", alpha)

	aL, _ := Generate_a_L(v, n)
	aR := Generate_a_R(aL)
	_commitA := CommitVectors(G, H, aL, aR)
	_commitA1 := CommitSingle(h, alpha)
	var commitA bn254.G1Affine
	commitA.Add(&_commitA, &_commitA1)

	//generate commitS
	rho, _ := rand.Int(rand.Reader, P)
	/* */
	//fmt.Println("rho:", rho)

	sL := Generate_s(n)
	sR := Generate_s(n)
	_commitS := CommitVectors(G, H, sL, sR)
	_commitS1 := CommitSingle(h, rho)
	var commitS bn254.G1Affine
	commitS.Add(&_commitS, &_commitS1)

	//generate challenge y,z
	y := Challenge_yz(commitV, g, h, commitA, commitS, int64(1))
	z := Challenge_yz(commitV, g, h, commitA, commitS, int64(2))

	//generate commitT1,commitT2
	tau1, _ := rand.Int(rand.Reader, P)
	tau2, _ := rand.Int(rand.Reader, P)
	//t1,t2
	yn := GenerateY(y, n)
	srYn := CalHadamardVec(sR, yn)
	//t2
	t2 := Inner_produ(sL, srYn)
	//t1
	sum := big.NewInt(0)
	//t11
	y2n := Generate2n(n)
	sl2n := Inner_produ(sL, y2n)
	z2 := big.NewInt(0)
	z2.Mul(&z, &z)
	z2.Mod(z2, P)
	t11 := big.NewInt(0)
	t11.Mul(z2, sl2n)
	t11.Mod(t11, P)
	//t12
	t12 := Inner_produ(sL, CalHadamardVec(yn, aR))
	//t13
	t13 := Inner_produ(CalVectorTimes(sL, &z), yn)
	//t14
	t14 := Inner_produ(CalVectorSub(aL, GenerateZ(z, n)), CalHadamardVec(yn, sR))
	_sum := big.NewInt(0)
	_sum.Add(t11, t12)
	_sum.Mod(_sum, P)
	sum.Add(t13, t14)
	sum.Mod(sum, P)
	t1 := big.NewInt(0)
	t1.Add(sum, _sum)
	t1.Mod(t1, P)
	commitT1 := Commit(g, h, t1, tau1)
	commitT2 := Commit(g, h, t2, tau2)

	//generate challenge x
	x := Challenge_x(commitV, g, h, commitA, commitS, commitT1, commitT2)

	//generate response
	taux := Calculate_taux(tau1, tau2, x, z, gamma)
	miu := Calculate_miu(alpha, rho, x)
	lx := Calculate_lx(aL, z, n, sL, x)
	rx := Calculate_rx(yn, aR, z, n, sR, x)
	tx := Calculate_tx(lx, rx)

	//verify
	//know lx,rx,tx
	veritx := Calculate_tx(lx, rx)
	//know y,z calculate δ(y,z)
	veriyn := GenerateY(y, n)
	veriz2 := big.NewInt(0)
	veriz2.Mul(&z, &z)
	veriz2.Mod(veriz2, P)
	veriz3 := big.NewInt(0)
	veriz3.Mul(veriz2, &z)
	veriz3.Mod(veriz3, P)
	z_z2 := big.NewInt(0)
	z_z2.Sub(&z, veriz2)
	z_z2.Mod(z_z2, P)
	y1n := Inner_produ(GenerateZ(*big.NewInt(1), n), veriyn)
	y2n1 := Inner_produ(GenerateZ(*big.NewInt(1), n), y2n)
	z_z2y1n := big.NewInt(0)
	z_z2y1n.Mul(z_z2, y1n)
	z_z2y1n.Mod(z_z2y1n, P)
	z3y2n1 := big.NewInt(0)
	z3y2n1.Mul(veriz3, y2n1)
	z3y2n1.Mod(z3y2n1, P)
	delta := big.NewInt(0)
	delta.Sub(z_z2y1n, z3y2n1)
	delta.Mod(delta, P)
	//know tx,taux,V,x,T1,T2,delta(calculated)
	verix2 := big.NewInt(0)
	verix2.Mul(&x, &x)
	verix2.Mod(verix2, P)
	commit0 := Commit(g, h, tx, taux)
	commitVg := Commit(commitV, g, veriz2, delta)
	commitT := Commit(commitT1, commitT2, &x, verix2)
	var commitVgT bn254.G1Affine
	commitVgT.Add(&commitVg, &commitT)
	//know A,S,x,z,y
	H1 := GenerateH1(H, y, n, P)
	commitAS := Commit(commitA, commitS, big.NewInt(1), &x)
	vec := CalVectorAdd(CalVectorTimes(veriyn, &z), CalVectorTimes(y2n, veriz2))
	commitvec := CommitSingleVector(H1, vec)
	z1 := GenerateZ1(z, n)
	commitz1 := CommitSingleVector(G, z1)
	var _commitP bn254.G1Affine
	_commitP.Add(&commitAS, &commitz1)
	var commitP bn254.G1Affine
	commitP.Add(&_commitP, &commitvec)
	//know miu,lx,rx
	commitmiu := CommitSingle(h, miu)

	commitlr := CommitVectors(G, H1, lx, rx)
	var verip bn254.G1Affine
	verip.Add(&commitmiu, &commitlr)

	//debug
	fmt.Println("tx==<lx,rx>:(true is 0)", veritx.Cmp(tx))
	fmt.Println("commit0==commitVgT:", commit0.Equal(&commitVgT))
	fmt.Println("veriP==commitP:", verip.Equal(&commitP))
}
