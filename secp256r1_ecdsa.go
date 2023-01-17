package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

/** Program entry point, establishes keys and message */
func run_ecdsa() {
	rnd := rand.Reader
	// Get generator point for curve
	secp256r1 := elliptic.P256()
	g := ecdsa.PublicKey{
		Curve: secp256r1,
		X:     secp256r1.Params().Gx,
		Y:     secp256r1.Params().Gy,
	}

	// Generate a 256 bit random secret key
	d_a_bytes := make([]byte, 32)
	rnd.Read(d_a_bytes)
	d_a := new(big.Int).SetBytes(d_a_bytes)

	// Get the public verification key dₐ × G
	pub_x, pub_y := g.ScalarBaseMult(d_a_bytes)
	Q_a := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     pub_x,
		Y:     pub_y,
	}

	message := make([]byte, 5242880) //random 5mb
	rnd.Read(message)

	// Sign data using private signing key
	r, s := sign_message_ecdsa(&message, d_a)
	// message[0] ^= 1 // bit flip test
	res := verify_ecdsa_sig(&Q_a, r, s, &message)
	println("Verified: ", res)
}

/*
Signing a message:

	This approach Implements the following NIST Specification:
	NIST FIPS 186-4 Section 6
	Supported by:
	https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

	msg: pointer to message to be signed
	d_a: private signing key which corresponds to public verification key Q_a
	return: signature (r, s)
*/
func sign_message_ecdsa(msg *[]byte, d_a *big.Int) (*big.Int, *big.Int) {

	secp256r1 := elliptic.P256()       // aka secp256r1
	n := secp256r1.Params().Params().N // curve order
	rnd := rand.Reader                 // cryptographically secure PRNG

	// 1. calculate e = HASH(M) ← here we use sha256
	e := sha256.Sum256(*msg)

	// 2. Let Z be Lₙ leftmost bits of e, where Lₙ is bit length of group order
	// n ← 256 bits for secp256r1
	z := new(big.Int).SetBytes(e[:32]) //FIPS 186-4 Sec 6.4

	// 3. select cryptographically secure random integer k from [1, n-1].
	//	  k cannot = n or 0 because (n⁻¹ mod n), (0⁻¹ mod n) do not exist
	k_bytes := make([]byte, 32+8) // FIPS 186-4 Appendix B.5.2 get N + 64 extra bits
	rnd.Read(k_bytes)
	k := new(big.Int).SetBytes(k_bytes)
	one := big.NewInt(1)
	k = k.Add(k, one)   // assure non-zero k
	k = k.Mod(k, n)     // assure k in valid range.
	k_bytes = k.Bytes() // Security Remark: unknown if golang big.Int operations are constant ops

	// 4. Get curve point (x1, y1) = k × G
	// Generator point for curve
	g := ecdsa.PublicKey{
		Curve: secp256r1,
		X:     secp256r1.Params().Gx,
		Y:     secp256r1.Params().Gy,
	}
	// Remark: it is sufficient in this case to discard the y coordinate
	// and recover it algorithmically if needed.
	// This reduces storage and transmission resource consumption.
	x1, _ := g.ScalarBaseMult(k_bytes) // k × G

	// 5. Calculate r = x₁ mod n, if r = 0, get a new k
	// if r = 0 then r*dₐ = 0 and s = k⁻¹(z), so adversary has z and can
	// recover k⁻¹ and thus k and can forge signatures
	r := new(big.Int).Mod(x1, n)

	// 6. calculate s = k⁻¹(z + rdₐ) mod n if S = 0, get a new k
	// S cannot = 0 becase 0⁻¹ mod n does not exist
	k_inv := new(big.Int).ModInverse(k, n) // SECURITY NOTE: big.Int modInv is not constant ops
	s := new(big.Int).Mul(k_inv, new(big.Int).Add(z, new(big.Int).Mul(r, d_a)))
	s = new(big.Int).Mod(s, n)

	// 7. sig is pair (r, s)
	return r, s
}

/*
Verifies a signature (r, s) against a public key Qₐ
Remark: by https://www.secg.org/sec1-v2.pdf 4.1.6 (page 47)
It is possible to recover Qₐ from (r, s)
This can reduce signature and transmission size requirements.

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

	// Phase 1: Public Key verification: (Check that public key is curve point)
	// 1. Check Qₐ != 𝒪
	// 2. Check Qₐ ∈ 𝔼
	// 3. Check n × Qₐ = 𝒪
	n_x, n_y := g.ScalarBaseMult(n.Bytes()) // get the neutral point for curve
	not_neutral := n_x != Q_a.X && n_y != Q_a.Y
	on_curve := g.IsOnCurve(Q_a.X, Q_a.Y)
	test_x, test_y := g.ScalarMult(Q_a.X, Q_a.Y, n.Bytes())
	qa_times_n_is_neutral := test_x.Cmp(n_x) == 0 && test_y.Cmp(n_y) == 0

	// Phase 2: Signature verification
	if not_neutral && on_curve && qa_times_n_is_neutral {
		// 1. Check that r, s ∈ [1...n−1]
		one := big.NewInt(1)
		if r.Cmp(n) < 0 && r.Cmp(one) > 0 &&
			s.Cmp(n) < 0 && s.Cmp(one) > 0 {

			// 2. Calculate e using same hash function as signature generation
			e := sha256.Sum256(*msg)
			// 3. Let Z be Lₙ leftmost bits of e, where Lₙ is bit length of
			// group order n ← 256 bits for secp256k1
			z := new(big.Int).SetBytes(e[:32])
			// 4.a. u₁ = zs⁻¹ mod n
			s_inv := new(big.Int).ModInverse(s, n) // Compute s⁻¹ only once
			zs_inv := new(big.Int).Mul(z, s_inv)
			u1 := new(big.Int).Mod(zs_inv, n)

			// 4.b. u₂ = rs⁻¹ mod n
			u2 := new(big.Int).Mul(r, s_inv)
			u2 = new(big.Int).Mod(u2, n)

			// 5. Calculate curve point (x₁, y₁) = u₁ × G + u₂ × Qₐ
			// if (x₁, y₁) = 𝒪 then signature is invalid because for curves in
			// Weierstrass form, 𝒪 is conventionally represented
			// by a point that doesn’t satisfy the curve equation.
			x1, y1 := g.ScalarBaseMult(u1.Bytes())

			// Remark: possible to reduce number of multiplcations here
			x2, y2 := g.ScalarMult(Q_a.X, Q_a.Y, u2.Bytes())
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
