package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func main() {

	//Get 5mb random data
	rnd := rand.Reader
	data := make([]byte, 5242880)
	rnd.Read(data)

	// Get generator point for curve
	secp256r1 := elliptic.P256()
	g := ecdsa.PublicKey{
		Curve: secp256r1,
		X:     secp256r1.Params().Gx,
		Y:     secp256r1.Params().Gy,
	}

	d_a_bytes := make([]byte, 32)
	rnd.Read(d_a_bytes)
	d_a := big.NewInt(0).SetBytes(d_a_bytes)
	pub_x, pub_y := g.ScalarBaseMult(d_a_bytes)
	// Get the public verification key dₐ × G
	Q_a := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     pub_x,
		Y:     pub_y,
	}

	// Check that public key is valid curve point and if not, get a new one
	point_on_curve := secp256r1.IsOnCurve(pub_x, pub_y)
	for !point_on_curve {
		// Generate a 32 byte secret key
		rnd.Read(d_a_bytes)
		d_a = big.NewInt(0).SetBytes(d_a_bytes)
		pub_x, pub_y := g.ScalarBaseMult(d_a_bytes)
		// Get the public verification key dₐ × G
		Q_a = ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     pub_x,
			Y:     pub_y,
		}
		point_on_curve = secp256r1.IsOnCurve(pub_x, pub_y)
	}
	// Sign data using private signing key
	r, s := sign_message_ecdsa(&data, d_a)
	res := verify_ecdsa_sig(&Q_a, r, s, &data)
	println(res)
}

/*
Signing a message:

	This approach relies on specifications obtained from:
	NIST FIPS 186-4 Section 6
	https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

	msg: pointer to message to be signed
	d_a: private signing key which corresponds to public signing key Q_a
	return: signature (r, s)
*/
func sign_message_ecdsa(msg *[]byte, d_a *big.Int) (*big.Int, *big.Int) {

	secp256r1 := elliptic.P256()       // aka secp256r1
	n := secp256r1.Params().Params().N // curve order
	rnd := rand.Reader                 // cryptographically secure PRNG

	// 1. calculate e = HASH(M) ← here we use sha256
	e := sha256.Sum256(*msg)

	// 2. Let Z be Lₙ leftmost bits of e, where Lₙ is bit length of if group order n ← 256 bits for secp256k1
	z := big.NewInt(0).SetBytes(e[:32]) //FIPS 186-4 Sec 6.4

	// 3. select cryptographically secure random integer k from [1, n-1]
	k_bytes := make([]byte, 32+8) // FIPS 186-4 Appendix B.5.2 get N + 64 extra bits to reduce bias from mod function
	rnd.Read(k_bytes)
	k := big.NewInt(0).SetBytes(k_bytes)
	k.Add(k, big.NewInt(1)) // assure non-zero k
	k = k.Mod(k, n)
	k = k.Sub(k, big.NewInt(1)) // assure k leq n-1
	k_bytes = k.Bytes()         // Remark: unknown if golang big.Int operations are constant ops

	// 4. Get curve point (x1, y1) = k × G
	// Remark: it is sufficient in this case to discard the y coordinate
	// and recover it algorithmically if needed. This reduces storage and transmission resource consumption.

	// Generator point for curve
	g := ecdsa.PublicKey{ //it may be verbose to define g this way but I want to be explicity clear about every step
		Curve: secp256r1,
		X:     secp256r1.Params().Gx,
		Y:     secp256r1.Params().Gy,
	}
	x1, _ := g.ScalarBaseMult(k_bytes) // k × G

	// 5. Calculate r = x₁ mod n, if r = 0, go to step 3
	r := big.NewInt(0).Mod(x1, n)
	k_inv := big.NewInt(0).ModInverse(k, n) //SECURITY NOTE: big.Int modInv is not constant ops afik

	// 6. calculate s = k⁻¹(z + rdA) mod n if S = 0, go to step 3
	s := big.NewInt(0).Mul(k_inv, big.NewInt(0).Add(z, big.NewInt(0).Mul(r, d_a)))
	s = big.NewInt(0).Mod(s, n)

	// 7. sig is pair (r, s)
	return r, s
}

/*
Verifies a signature (r, s) against a public key Qₐ

	returns true iff signature is validated against key
*/
func verify_ecdsa_sig(Q_a *ecdsa.PublicKey, r, s *big.Int, msg *[]byte) bool {

	//Define curve, n, and generator point
	secp256r1 := elliptic.P256() // aka secp256r1
	n := secp256r1.Params().Params().N
	g := ecdsa.PublicKey{
		Curve: secp256r1,
		X:     secp256r1.Params().Gx,
		Y:     secp256r1.Params().Gy,
	}

	// Phase 1: Public Key verification: (Check that the key is a valid member of group defined by curve)
	// 1. Check Qₐ != 𝒪
	// 2. Check Qₐ ∈ 𝔼
	// 3. Check n × Qₐ = 𝒪
	n_x, n_y := g.ScalarBaseMult(n.Bytes()) //get the neutral point for curve
	not_neutral := n_x != Q_a.X && n_y != Q_a.Y
	on_curve := g.IsOnCurve(Q_a.X, Q_a.Y)
	test_x, test_y := g.ScalarMult(Q_a.X, Q_a.Y, n.Bytes())
	qa_times_n_is_neutral := test_x.Cmp(n_x) == 0 && test_y.Cmp(n_y) == 0

	if not_neutral && on_curve && qa_times_n_is_neutral {
		// Check that r, s ∈ [1...n−1] Remark: r, s must belong to this set because mod fails otherwise
		one := big.NewInt(1)
		if r.Cmp(n) < 0 && r.Cmp(one) > 0 &&
			s.Cmp(n) < 0 && s.Cmp(one) > 0 {

			// Phase 2: Signature verification
			g := ecdsa.PublicKey{
				Curve: secp256r1,
				X:     secp256r1.Params().Gx,
				Y:     secp256r1.Params().Gy,
			}

			// 2. Calculate e using same hash function as signature generation
			e := sha256.Sum256(*msg)
			// 3. Let Z be Lₙ leftmost bits of e, where Lₙ is bit length of if group order n ← 256 bits for secp256k1
			z := big.NewInt(0).SetBytes(e[:32])

			// 4.a. u₁ = zs⁻¹ mod n
			s_inv := big.NewInt(0).ModInverse(s, n) //Compute s⁻¹ only once
			zs_inv := big.NewInt(0).Mul(z, s_inv)
			u1 := big.NewInt(0).Mod(zs_inv, n)

			// 4.b. u₂ = rs⁻¹ mod n
			u2 := big.NewInt(0).Mul(r, s_inv)
			u2 = big.NewInt(0).Mod(u2, n)

			// 5. Calculate curve point (x₁, y₁) = u₁ × G + u₂ × Qₐ
			// if (x₁, y₁) = 𝒪 then signature is invalid, because we said in signing that 0 is not a valid
			// value for r or S. The neutral point for secp256r1 in projective coords is (0:1:0)
			x1, y1 := g.ScalarBaseMult(u1.Bytes())
			x2, y2 := g.ScalarMult(Q_a.X, Q_a.Y, u2.Bytes()) //Remark: possible to reduce number of multiplcations here
			res_x, _ := g.Add(x1, y1, x2, y2)

			// 6. Signature is valid iff r ≡ x₁ mod n
			return res_x.Cmp(r) == 0
		} else {
			// r and/or s not in valid range
			return false
		}
	} else {
		// public key invalid
		return false
	}
}
