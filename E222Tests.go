package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func e222_tests() {

	Zero()
	One()
	GPlusMinusG()
	TwoTimesG()
	FourTimesG()
	NotZero()
	rTimesG()
	TestkTimesGAndkmodRTimesG()
	TestkPlus1TimesG()
	ktTimesgEqualskgtg()
	ktpEqualstkGEqualsktmodrG()

}

func Zero() {

	passedTestCount := 0
	numberOfTests := 100
	for i := 0; i < numberOfTests; i++ {
		G := E222IdPoint()
		if G.SecMul(big.NewInt(0)).Equals(E222IdPoint()) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func One() {

	passedTestCount := 0
	numberOfTests := 100
	for i := 0; i < numberOfTests; i++ {
		G := E222GenPoint()
		if G.SecMul(big.NewInt(1)).Equals(E222GenPoint()) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func GPlusMinusG() {

	passedTestCount := 0
	numberOfTests := 100
	for i := 0; i < numberOfTests; i++ {
		G := E222GenPoint()
		if G.Add(E222GenPoint().getOpposite()).Equals(E222IdPoint()) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func TwoTimesG() {

	passedTestCount := 0
	numberOfTests := 1
	for i := 0; i < numberOfTests; i++ {
		G := E222GenPoint()
		p := G.SecMul(big.NewInt(2))
		fmt.Println(p.x.String())
		fmt.Println(p.y.String())
		if G.SecMul(big.NewInt(2)).Equals(G.Add(G)) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func FourTimesG() {

	passedTestCount := 0
	numberOfTests := 100
	for i := 0; i < numberOfTests; i++ {
		G := E222GenPoint()
		if G.SecMul(big.NewInt(4)).Equals(G.SecMul(big.NewInt(2)).SecMul(big.NewInt(2))) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func NotZero() {

	passedTestCount := 0
	numberOfTests := 100
	for i := 0; i < numberOfTests; i++ {
		G := E222GenPoint()
		if !G.SecMul(big.NewInt(4)).Equals(E222IdPoint()) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)

}

func rTimesG() {

	passedTestCount := 0
	numberOfTests := 100
	for i := 0; i < numberOfTests; i++ {
		G := E222GenPoint()
		if G.SecMul(&G.r).Equals(E222IdPoint()) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func TestkTimesGAndkmodRTimesG() {
	G := E222GenPoint()
	R := G.getR()

	passedTestCount := 0
	numberOfTests := 50
	for i := 0; i < numberOfTests; i++ {
		k := generateRandomBigInt()
		G1 := G.SecMul(k)
		G2 := G.SecMul(k.Mod(k, &R))
		if G1.Equals(G2) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func TestkPlus1TimesG() {

	passedTestCount := 0
	numberOfTests := 50
	for i := 0; i < numberOfTests; i++ {
		k := generateRandomBigInt()
		G2 := E222GenPoint().SecMul(k)
		G2 = G2.Add(E222GenPoint())
		k = k.Add(k, big.NewInt(1))
		G1 := E222GenPoint().SecMul(k)
		if G1.Equals(G2) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func ktTimesgEqualskgtg() {

	passedTestCount := 0
	numberOfTests := 50
	for i := 0; i < numberOfTests; i++ {
		k := generateRandomBigInt()
		t := generateRandomBigInt()

		G2 := E222GenPoint().SecMul(k)
		G2 = G2.Add(E222GenPoint().SecMul(t))

		x := new(big.Int).Add(k, t)
		G1 := E222GenPoint().SecMul(x)

		if G1.Equals(G2) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

func ktpEqualstkGEqualsktmodrG() {

	passedTestCount := 0
	numberOfTests := 50
	for i := 0; i < numberOfTests; i++ {
		k := generateRandomBigInt()
		t := generateRandomBigInt()

		ktP := E222GenPoint().SecMul(t).SecMul(k)
		tkG := E222GenPoint().SecMul(k).SecMul(t)

		ktmodr := k.Mul(k, t)
		ktmodr = ktmodr.Mod(ktmodr, &E222GenPoint().r)
		ktmodrG := E222GenPoint().SecMul(ktmodr)

		if ktP.Equals(tkG) && ktP.Equals(ktmodrG) {
			passedTestCount++
		} else {
			break
		}
	}
	fmt.Println("Test passed: ", passedTestCount == numberOfTests)
}

// gengerates random 512 bit integer
func generateRandomBigInt() *big.Int {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return nil
	}
	random := big.NewInt(0)
	random.SetBytes(b)
	return random
}
