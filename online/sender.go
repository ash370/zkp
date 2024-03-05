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

func SigmaProtocol() {
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

	starttime := time.Now()
	/*                              sigma protocol 1                                */
	//commit
	_t1, _ := rand.Int(rand.Reader, params.Order)
	var t1 bn254.PointAffine
	t1.ScalarMultiplication(&_h, _t1)

	_t2, _ := rand.Int(rand.Reader, params.Order)
	var t2 bn254.PointAffine
	var tmp1 bn254.PointAffine
	tmp1.ScalarMultiplication(&_publickey, _t1)
	var tmp2 bn254.PointAffine
	tmp2.ScalarMultiplication(&_g0, _t2)
	t2.Add(&tmp1, &tmp2)

	/*                              sigma protocol 2                                */
	//commit
	_tb, _ := rand.Int(rand.Reader, params.Order)
	_tr, _ := rand.Int(rand.Reader, params.Order)
	var tplain bn254.PointAffine
	tplain.ScalarMultiplication(&_trans, _tb)
	tC := apublickey.Encrypt(params, tplain, _tr)

	/*                              sigma protocol 1&2                                */
	//challenge
	hashFunc := hash.MIMC_BN254
	mimc := hashFunc.New()
	var _tmpmsg1 []byte
	_tmpmsg1 = append(_tmpmsg1, t1.Marshal()...)
	var _tmpmsg2 []byte
	_tmpmsg2 = append(_tmpmsg1, t2.Marshal()...)
	var _tmpmsg []byte
	_tmpmsg = append(_tmpmsg, txs.A.Marshal()...)
	var tmpmsg []byte
	tmpmsg = append(_tmpmsg, txs.B.Marshal()...)
	var _tC1 []byte
	_tC1 = append(_tC1, tC.A.Marshal()...)
	var _tC2 []byte
	_tC2 = append(_tC1, tC.B.Marshal()...)
	var _data1 []byte
	_data1 = append(_data1, _tmpmsg2...)
	var _data2 []byte
	_data2 = append(_data1, tmpmsg...)
	var _data3 []byte
	_data3 = append(_data2, _tC2...)
	var data []byte
	data = append(data, _data3...)
	mimc.Write(data)
	_challenge := mimc.Sum(nil)
	var challenge big.Int
	challenge.SetBytes(_challenge)

	/*                              sigma protocol 1                                */
	//response
	var _z1 big.Int
	_z1.Mul(&challenge, r)
	var z1 big.Int
	z1.Add(&_z1, _t1)

	var _z2 big.Int
	_z2.Mul(&challenge, &v)
	var z2 big.Int
	z2.Add(&_z2, _t2)

	/*                              sigma protocol 2                                */
	//response
	var _tz1 big.Int
	_tz1.Mul(&challenge, rb)
	var tz1 big.Int
	tz1.Add(&_tz1, _tr)

	var _tz2 big.Int
	_tz2.Mul(&challenge, &b)
	var tz2 big.Int
	tz2.Add(&_tz2, _tb)

	/*                              sigma protocol 1                                */
	//verify
	//l
	var z1h bn254.PointAffine
	z1h.ScalarMultiplication(&_h, &z1)
	var z1pk bn254.PointAffine
	z1pk.ScalarMultiplication(&_publickey, &z1)
	var z2g0 bn254.PointAffine
	z2g0.ScalarMultiplication(&_g0, &z2)
	var z1pkz2g0 bn254.PointAffine
	z1pkz2g0.Add(&z1pk, &z2g0)
	//r
	var _z1r bn254.PointAffine
	_z1r.ScalarMultiplication(&txs.B, &challenge)
	var z1r bn254.PointAffine
	z1r.Add(&t1, &_z1r)
	var _z2r bn254.PointAffine
	_z2r.ScalarMultiplication(&txs.A, &challenge)
	var z2r bn254.PointAffine
	z2r.Add(&_z2r, &t2)

	/*                              sigma protocol 2                                */
	//verify
	//l
	var vplain bn254.PointAffine
	vplain.ScalarMultiplication(&_trans, &tz2)
	vl := apublickey.Encrypt(params, vplain, &tz1)
	//r
	var _tc1r bn254.PointAffine
	_tc1r.ScalarMultiplication(&apublickey.pk, _tr)
	var tc1r bn254.PointAffine
	tc1r.Add(&_tc1r, &tplain)
	var _challengeC1 bn254.PointAffine
	_challengeC1.ScalarMultiplication(&C.A, &challenge)
	var vr1 bn254.PointAffine
	vr1.Add(&_challengeC1, &tc1r)
	var _tc2r bn254.PointAffine
	_tc2r.ScalarMultiplication(&_g, _tr)
	var _challengeC2 bn254.PointAffine
	_challengeC2.ScalarMultiplication(&C.B, &challenge)
	var vr2 bn254.PointAffine
	vr2.Add(&_challengeC2, &_tc2r)

	endtime := time.Now()

	//debug
	fmt.Println("z1*h==t1+challenge*c1:", z1h.Equal(&z1r))
	fmt.Println("z1pkz2g0==t2+challenge*c2:", z1pkz2g0.Equal(&z2r))
	fmt.Println("vl1==vr1:", vl.A.Equal(&vr1))
	fmt.Println("vl2==vr2:", vl.B.Equal(&vr2))
	fmt.Println("response time:", endtime.Sub(starttime))
}
