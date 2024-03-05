package online

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecct "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func SigmaProtocolf() {
	params, _ := twistededwards.GetCurveParams(ecct.BN254)

	/*                              sigma protocol 1                                */
	//witness: transfer v, encryption randomness r
	var v big.Int
	v.SetString("100", 10)

	r, _ := rand.Int(rand.Reader, params.Order)

	/*                              sigma protocol 2                                */
	//witness: balance b, encryption randomness rb
	var b big.Int
	b.SetString("200", 10)
	rb, _ := rand.Int(rand.Reader, params.Order)

	/*                              sigma protocol 1                                */
	//public: TX_s=(v*g0+r*pks^prime,r*h), h, pks^prime, g0
	_privatekey, _ := rand.Int(rand.Reader, params.Order)
	var _h bn254.PointAffine
	_h.X.SetBigInt(params.Base[0])
	_h.Y.SetBigInt(params.Base[1])
	var _publickey bn254.PointAffine
	_publickey.ScalarMultiplication(&_h, _privatekey)

	publickey := elPublickey{_publickey}

	var _g0 bn254.PointAffine
	_g0.X.SetBigInt(params.Base[0])
	_g0.Y.SetBigInt(params.Base[1])
	var plain bn254.PointAffine
	plain.ScalarMultiplication(&_g0, &v)
	txs := publickey.Encrypt(params, plain, r)

	/*                              sigma protocol 2                                */
	//public: C=(rb*pka+b,rb*g), g, pka
	_aprivatekey, _ := rand.Int(rand.Reader, params.Order)
	var _g bn254.PointAffine
	_g.X.SetBigInt(params.Base[0])
	_g.Y.SetBigInt(params.Base[1])
	var _apublickey bn254.PointAffine
	_apublickey.ScalarMultiplication(&_g, _aprivatekey)

	apublickey := elPublickey{_apublickey}

	var _trans bn254.PointAffine
	_trans.X.SetBigInt(params.Base[0])
	_trans.Y.SetBigInt(params.Base[1])
	var aplain bn254.PointAffine
	aplain.ScalarMultiplication(&_trans, &b)
	C := apublickey.Encrypt(params, aplain, rb)

	/* */
	starttime := time.Now()

	var commit commitMent
	para1 := commit.ParamsGen(params)
	para2 := commit.ParamsGen(params)
	_tb := commit.ParamsGen(params)
	_tr := commit.ParamsGen(params)

	t1 := commit.Commitmul(para1, _h)
	t2 := commit.Commitmuladd(para1, para2, _publickey, _g0)
	tC := commit.CommitencValid(_tb, _tr, apublickey, params, _trans)

	hashFunc := hash.MIMC_BN254
	mimc := hashFunc.New()

	var data []byte
	data = append(data, t1.commit.Marshal()...)
	data = append(data, t2.commit.Marshal()...)
	data = append(data, txs.A.Marshal()...)
	data = append(data, txs.B.Marshal()...)
	data = append(data, tC.commit.A.Marshal()...)
	data = append(data, tC.commit.B.Marshal()...)

	mimc.Write(data)
	_challenge := mimc.Sum(nil)
	var challenge big.Int
	challenge.SetBytes(_challenge)

	var rp1 response
	rp1 = rp1.Response(para1, challenge, r)
	var rp2 response
	rp2 = rp2.Response(para2, challenge, &v)

	var tz1 response
	tz1 = tz1.Response(_tr, challenge, rb)
	var tz2 response
	tz2 = tz2.Response(_tb, challenge, &b)

	var z1h bn254.PointAffine
	z1h.ScalarMultiplication(&_h, &rp1.rp)
	var z1pk bn254.PointAffine
	z1pk.ScalarMultiplication(&_publickey, &rp1.rp)
	var z2g0 bn254.PointAffine
	z2g0.ScalarMultiplication(&_g0, &rp2.rp)
	var z1pkz2g0 bn254.PointAffine
	z1pkz2g0.Add(&z1pk, &z2g0)

	var _z1r bn254.PointAffine
	_z1r.ScalarMultiplication(&txs.B, &challenge)
	var z1r bn254.PointAffine
	z1r.Add(&t1.commit, &_z1r)
	var _z2r bn254.PointAffine
	_z2r.ScalarMultiplication(&txs.A, &challenge)
	var z2r bn254.PointAffine
	z2r.Add(&_z2r, &t2.commit)

	var vplain bn254.PointAffine
	vplain.ScalarMultiplication(&_trans, &tz2.rp)
	vl := apublickey.Encrypt(params, vplain, &tz1.rp)

	var _tc1r bn254.PointAffine
	_tc1r.ScalarMultiplication(&apublickey.pk, _tr.r)
	var tc1r bn254.PointAffine
	var tplain bn254.PointAffine
	tplain.ScalarMultiplication(&_trans, _tb.r)
	tc1r.Add(&_tc1r, &tplain)
	var _challengeC1 bn254.PointAffine
	_challengeC1.ScalarMultiplication(&C.A, &challenge)
	var vr1 bn254.PointAffine
	vr1.Add(&_challengeC1, &tc1r)
	var _tc2r bn254.PointAffine
	_tc2r.ScalarMultiplication(&_g, _tr.r)
	var _challengeC2 bn254.PointAffine
	_challengeC2.ScalarMultiplication(&C.B, &challenge)
	var vr2 bn254.PointAffine
	vr2.Add(&_challengeC2, &_tc2r)

	endtime := time.Now()

	fmt.Println("z1*h==t1+challenge*c1:", z1h.Equal(&z1r))
	fmt.Println("z1pkz2g0==t2+challenge*c2:", z1pkz2g0.Equal(&z2r))
	fmt.Println("vl1==vr1:", vl.A.Equal(&vr1))
	fmt.Println("vl2==vr2:", vl.B.Equal(&vr2))
	fmt.Println("response time:", endtime.Sub(starttime))
}
