package main

import (
	"math/big"
)

/**
 * E222 Elliptic Curve (Edward's Curve) of equation: (x²) + (y²) = 1 + d(x²)(y²)
 * where d = 160102
 * Contains methods to add and multiply points on curve using scalar values.
 */
type E222 struct {
	x big.Int //X coordinate
	y big.Int // Y cooridinate
	p big.Int // Mersenne prime defining a finite field F(p) = 2²²²−117
	d big.Int // d = 160102
	r big.Int // number of points on Curve -> n := 4 * (R) .
	n big.Int //4 * r
}

// number of points on Curve -> n := 4 * (R) .
func (e *E222) getR() big.Int {
	R, _ := new(big.Int).SetString("1684996666696914987166688442938726735569737456760058294185521417407", 10)
	return *R
}

// Mersenne prime defining a finite field F(p) = 2²²²−117
func (e *E222) getP() big.Int {
	P := new(big.Int).Sub(big.NewInt(2).Exp(big.NewInt(2), big.NewInt(222), nil), big.NewInt(117))
	return *P
}

// constructor for E222 for any x, y
func NewE222XY(x, y big.Int) *E222 {
	tempR := new(E222).getR()
	point := E222{
		x: x,
		y: y,
		p: new(E222).getP(),
		d: *big.NewInt(160102),
		r: tempR,
		n: *new(E222).r.Mul(&tempR, big.NewInt(4)),
	}
	return &point
}

// constructor for E222, solves for y
func NewE222X(x big.Int, msb uint) *E222 {
	tempR := new(E222).getR()
	point := E222{
		x: x,
		y: *solveForY(&x, new(E222).getP(), msb),
		p: new(E222).getP(),
		d: *big.NewInt(160102),
		r: tempR,
		n: *new(E222).r.Mul(&tempR, big.NewInt(4)),
	}
	return &point
}

// Generator point for the curve
func E222GenPoint(msb uint) *E222 {
	tempR := new(E222).getR()

	P := new(E222).getP()
	X, _ := new(big.Int).SetString("2705691079882681090389589001251962954446177367541711474502428610129", 10)
	Y, _ := new(big.Int).SetString("28", 10)
	point := E222{
		x: *X,
		y: *Y,
		p: P,
		d: *big.NewInt(160102),
		r: tempR,
		n: *new(E222).r.Mul(&tempR, big.NewInt(4)),
	}
	return &point

}

// solves curve equation 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦² for y value
func solveForY(X *big.Int, P big.Int, msb uint) *big.Int {
	num := new(big.Int).Sub(big.NewInt(1), new(big.Int).Exp(X, big.NewInt(2), nil))
	// fmt.Println("num: ", num)
	num = num.Mod(num, &P)
	// fmt.Println("num mod p: ", num)
	denom := new(big.Int).Add(big.NewInt(1), (new(big.Int).Mul(big.NewInt(160102), new(big.Int).Exp(X, big.NewInt(2), nil))))
	// fmt.Println("denom: ", denom)
	denom = denom.Mod(denom, &P)
	// fmt.Println("denom mod p: ", denom)
	denom = new(big.Int).ModInverse(denom, &P)
	// fmt.Println("denom mod inv: ", denom)
	radicand := new(big.Int).Mul(num, denom)
	// fmt.Println("radicand: ", radicand)
	Y := sqrt(radicand, msb)
	// fmt.Println("y: ", Y)
	return Y
}

// The identity point of the curve (also refered to as "point at infinity").
// Equivalent to 0 in integer group.
func E222IdPoint() *E222 { return NewE222XY(*big.NewInt(0), *big.NewInt(1)) }

/*
Gets the opposite value of a point, defined as the following:
if P = (X, Y), opposite of P = (-X, Y).
*/
func (e *E222) getOpposite() *E222 { return NewE222XY(*e.x.Neg(&e.x), e.y) }

// Checks two points for equality by comparing their coordinates.
func (A *E222) Equals(B *E222) bool { return A.x.Cmp(&B.x) == 0 && A.y.Cmp(&B.y) == 0 }

/*
Adds two E222 points and returns another E222 curve point.
Point addition operation is defined as:

	(x1, y1) + (x2, y2) = ((x1y2 + y1x2) / (1 + (d)x1x2y1y2)), ((y1y2 - x1x2) / (1 - (d)x1x2y1y2))

where "/" is defined to be multiplication by modular inverse.
*/
func (A *E222) Add(B *E222) *E222 {

	x1, y1, x2, y2 := A.x, A.y, B.x, B.y

	xNum := new(big.Int).Add(new(big.Int).Mul(&x1, &y2), new(big.Int).Mul(&y1, &x2))
	xNum.Mod(xNum, &A.p)

	mul := new(big.Int).Mul(&A.d, &x1) //x1 * x2 *  y1 * y2
	mul = new(big.Int).Mul(mul, &x2)
	mul = new(big.Int).Mul(mul, &y1)
	mul = new(big.Int).Mul(mul, &y2)

	xDenom := new(big.Int).Add(big.NewInt(1), mul)
	xDenom.Mod(xDenom, &A.p)
	xDenom = new(big.Int).ModInverse(xDenom, &A.p)

	newX := new(big.Int).Mul(xNum, xDenom)
	newX.Mod(newX, &A.p)

	yNum := new(big.Int).Sub(new(big.Int).Mul(&y1, &y2), new(big.Int).Mul(&x1, &x2))
	yNum.Mod(yNum, &A.p)

	yDenom := new(big.Int).Sub(big.NewInt(1), mul)
	yDenom.Mod(yDenom, &A.p)
	yDenom = new(big.Int).ModInverse(yDenom, &A.p)

	newY := new(big.Int).Mul(yNum, yDenom)
	newY.Mod(newY, &A.p)

	return NewE222XY(*newX, *newY)
}

/*
EC Multiplication algorithm using the Montgomery Ladder approach to mitigate
power consumption side channel attacks. Mostly constructed around:

(pg 4.)	https://eprint.iacr.org/2014/140.pdf

S is a  scalar value to multiply by. S is a private key and should be kept secret.
Returns Curve.E222 point which is result of multiplication.
*/
func (r1 *E222) SecMul(S *big.Int) *E222 {
	r0 := NewE222XY(*big.NewInt(0), *big.NewInt(1))
	for i := S.BitLen(); i >= 0; i-- {
		if S.Bit(i) == 1 {
			r0 = r0.Add(r1)
			r1 = r1.Add(r1)
		} else {
			r1 = r0.Add(r1)
			r0 = r0.Add(r0)
		}
	}
	return r0 // r0 = P * s
}

/*
 * Compute a square root of v mod p with a specified
 * the least significant bit, if such a root exists.
 * Provided by Dr. Paulo Barretto.
 * @param v   the radicand.
 * lsb is desired least significant bit (true: 1, false: 0).
 * return a square root r of v mod p with r mod 2 = 1 iff lsb = true
 * if such a root exists, otherwise null.
 */
func sqrt(v *big.Int, lsb uint) *big.Int {

	if v.Sign() == 0 {
		return big.NewInt(0)
	}
	P := new(E222).getP()
	r := new(big.Int).Exp(v, new(big.Int).Add(new(big.Int).Rsh(&P, 2), big.NewInt(1)), &P)
	// fmt.Println("r value: ", r)
	if r.Bit(0) != lsb {
		r.Sub(&P, r) // correct the lsb }
		// fmt.Println("r sub value: ", r)
		bi := new(big.Int).Sub(new(big.Int).Mul(r, r), v)
		bi = bi.Mod(bi, &P)
		// fmt.Println("bi value: ", bi)
		if bi.Sign() == 0 {
			return r
		} else {
			return nil
		}
	}
	return r
}
