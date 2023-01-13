package main

/**
Implements SHA3XOF functionality as defined in FIPS PUP 202 and NIST SP 800-105.
	Inspiration:
	https://github.com/mjosaarinen/tiny_sha3
	https://keccak.team/keccak_specs_summary.html
	https://github.com/NWc0de/KeccakUtils
Dustin Ray
version 0.1
*/

import (
	"encoding/hex"
	"errors"
	"math/big"
	"time"
)

type Signature struct {
	M []byte   // 	message that was signed
	H *big.Int //	keyed hash of signed message
	Z *big.Int //	public nonce
}

/*
SHA3-Keccak functionaility ref NIST FIPS 202.

	N: pointer to message to be hashed.
	d: requested output length
*/
func SHAKE(N *[]byte, d int) []byte {
	bytesToPad := 136 - len(*N)%136 // SHA3-256 r = 1088 / 8 = 136
	if bytesToPad == 1 {
		*N = append(*N, 0x86)
	} else {
		*N = append(*N, 0x06)
	}
	return SpongeSqueeze(SpongeAbsorb(N, 2*d), d, 1600-(2*d))
}

/*
Computes SHA3-512 hash of byte array

	data: message to hash
	fileMode: determines wheter to process a file or text
	from the notepad.
	return: SHA3-512 hash of X
*/
func ComputeSHA3HASH(data *[]byte, fileMode bool) []byte {
	if fileMode {
		return []byte{}
	} else {
		return SHAKE(data, 512)
	}
}

/*
FIPS 202 Section 3 cSHAKE function returns customizable and
domain seperated length L SHA3XOF hash of input string.

	X: input message in bytes
	L: requested output length
	N: optional function name string
	S: option customization string
	return: SHA3XOF hash of length L of input message X
*/
func cSHAKE256(X *[]byte, L int, N string, S string) []byte {
	if N == "" && S == "" {
		return SHAKE(X, L)
	}
	out := bytepad(append(encodeString([]byte(N)), encodeString([]byte(S))...), 136)
	out = append(out, *X...)
	out = append(out, []byte{0x04}...) // https://keccak.team/keccak_specs_summary.html
	return SpongeSqueeze(SpongeAbsorb(&out, 512), L, 1600-512)
}

/*
Generates keyed hash for given input as specified in NIST SP 800-185 section 4.

	K: key
	X: byte-oriented message
	L: requested bit length
	S: customization string
	return: KMACXOF256 of X under K
*/
func KMACXOF256(K *[]byte, X *[]byte, L int, S string) []byte {
	newX := append(append(bytepad(encodeString(*K), 136), *X...), rightEncode(0)...)
	return cSHAKE256(&newX, L, "KMAC", S)
}

/*
Generates a (Schnorr/ECDHIES) key pair from passphrase pw:

	s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s //explain why we do this
	V <- s*G

	key pair: (s, V)
	key: a pointer to an empty KeyObj to be populated with user data
*/
func generateKeyPair(key *KeyObj, password, owner string) {
	pwBytes := []byte(password)
	s := new(big.Int).SetBytes(KMACXOF256(&pwBytes, &[]byte{}, 512, "K"))
	s = s.Mul(s, big.NewInt(4))
	s = s.Mod(s, &E521IdPoint().n)

	V := *E521GenPoint(0).SecMul(s)
	key.Owner = owner
	key.PrivKey = s.String()
	key.PubKeyX = V.x.String()
	key.PubKeyY = V.y.String()
	key.DateCreated = time.Now().Format(time.RFC1123)
	sigString := []byte(key.Owner + key.PubKeyX + key.PubKeyY + key.DateCreated)
	signed, _ := signWithKey(pwBytes, &sigString)
	sigHash := KMACXOF256(&pwBytes, signed, 512, "SIG")
	key.Signature = hex.EncodeToString(sigHash)

}

/*
Generates a signature for a byte array m under passphrase pw:

	s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s
	k <- KMACXOF256(s, m, 512, “N”); k <- 4k
	U <- k*G;
	h <- KMACXOF256(U x , m, 512, “T”); z <- (k – hs) mod r

	return: signature: (h, z)
*/
func signWithKey(pw []byte, message *[]byte) (*[]byte, error) {

	s := new(big.Int).SetBytes(KMACXOF256(&pw, &[]byte{}, 512, "K"))
	s = s.Mul(s, big.NewInt(4))
	V := *E521GenPoint(0)
	V = *V.SecMul(s)
	sBytes := s.Bytes()
	//get signing key for messsage under password
	k := new(big.Int).SetBytes(KMACXOF256(&sBytes, message, 512, "N"))
	k = new(big.Int).Mul(k, big.NewInt(4))
	//create public signing key for message
	U := E521GenPoint(0).SecMul(k)
	uXBytes := U.x.Bytes()
	//get the tag for the message key
	h := KMACXOF256(&uXBytes, message, 512, "T")
	//create public nonce for signature
	h_bigInt := new(big.Int).SetBytes(h)
	z := new(big.Int).Sub(k, new(big.Int).Mul(h_bigInt, s))
	z = new(big.Int).Mod(z, &E521IdPoint().r)
	// z = (k - hs) mod r
	sig := Signature{M: *message, H: h_bigInt, Z: z}
	result, err := encodeSignature(&sig)

	if err != nil {
		return nil, errors.New("failed to encode signature")
	} else {
		return result, nil
	}
}

/*
Verifies a signature (h, z) for a byte array m under the (Schnorr/
ECDHIES) public key V:

	U <- z*G + h*V
	sig: signature: (h, z)
	pubKey: E521 key V used to sign message m
	return: true if, and only if, KMACXOF256(U x , m, 512, “T”) = h
*/
func verify(pubkey *E521, sig *Signature, message *[]byte) bool {

	U2 := E521GenPoint(0).SecMul(sig.Z).Add(pubkey.SecMul(sig.H))
	UXbytes := U2.x.Bytes()
	h_p := KMACXOF256(&UXbytes, message, 512, "T")
	h2 := new(big.Int).SetBytes(h_p)
	if h2.Cmp(sig.H) != 0 {
		return false
	} else {
		return true
	}
}
