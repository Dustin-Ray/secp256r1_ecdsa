package main

/* Controller for MVC. Connects buttons to model functionality and
transmits messages to view from model. */

import (
	"encoding/hex"
	"math/big"

	"github.com/gotk3/gotk3/gtk"
)

// adds buttons in a factory style to fixed context
func createButtons(ctx *WindowCtx) {

	//list of button labels
	labelList := []string{"Compute Hash",
		"Generate Keypair", "Sign With Key", "Verify Signature"}

	buttonList := make([]gtk.Button, len(labelList))
	for i, label := range labelList {
		btn, _ := gtk.ButtonNewWithLabel(label)
		buttonList[i] = *btn
		ctx.fixed.Put(btn, 40, 80+i*45)
	}
	ctx.buttons = &buttonList
	setupResetButton(ctx)

	// Connect buttons to functions
	buttonList[0].Connect("clicked", func() { setSHA3Hash(ctx) })
	buttonList[1].Connect("clicked", func() { setKeyPair(ctx) })
	buttonList[2].Connect("clicked", func() { setEcSignature(ctx) })
	buttonList[3].Connect("clicked", func() { setEcVerify(ctx) })
}

// Create reset button
func setupResetButton(ctx *WindowCtx) {

	reset, _ := gtk.ButtonNewWithLabel("Reset")
	reset.SetName("resetButton")
	reset.Connect("clicked", func() {
		showRestWarningDialog(ctx)
	})
	ctx.fixed.Put(reset, 40, 510)
}

/* BUTTON CONSTRUCTION:*/

// Connects SHA3 hash function to button
func setSHA3Hash(ctx *WindowCtx) {
	(*ctx.buttons)[0].SetTooltipMarkup("Computes a SHA3-512 hash of the text in the notepad.")
	ctx.initialState = false
	ctx.fileMode = false
	text, _ := ctx.notePad.GetText(ctx.notePad.GetStartIter(), ctx.notePad.GetEndIter(), true)
	textBytes := []byte(text)
	ctx.notePad.SetText(hex.EncodeToString(ComputeSHA3HASH(&textBytes, ctx.fileMode)))
	ctx.updateStatus("SHA3-512 digest computed successfully")
}

// Connects keypari generation to button
func setKeyPair(ctx *WindowCtx) {
	(*ctx.buttons)[1].SetTooltipMarkup("Generates a Schnorr E521 keypair from supplied password.")
	ctx.initialState = false
	ctx.fileMode = false
	key := KeyObj{}
	opResult := constructKey(ctx, &key)
	if opResult {
		ctx.keytable.importKey(ctx, key)
		ctx.updateStatus("key " + key.Id + " generated successfully")
	} else {
		ctx.updateStatus("key generation cancelled")
	}
}

// Signs a message using a private key derived from a password.
func setEcSignature(ctx *WindowCtx) {
	(*ctx.buttons)[2].SetTooltipMarkup("Signs a message with a selected key.")
	ctx.initialState = false
	ctx.fileMode = false
	password, result := passwordEntryDialog(ctx.win, "signature")
	if result {
		text, _ := ctx.notePad.GetText(ctx.notePad.GetStartIter(), ctx.notePad.GetEndIter(), true)
		textBytes := []byte(text)
		signature, err := signWithKey([]byte(password), &textBytes)
		if err != nil {
			ctx.updateStatus(err.Error())
		} else {
			sigHexString := hex.EncodeToString(*signature)
			soapFmttedSig := getSOAP(&sigHexString, ctx, signatureBegin, signatureEnd) //refactor
			ctx.notePad.SetText(*soapFmttedSig)
			ctx.updateStatus("signature generated")
		}
	} else {
		ctx.updateStatus("signature cancelled")
	}
}

// Verifies signature using public key.
func setEcVerify(ctx *WindowCtx) {
	(*ctx.buttons)[3].SetTooltipMarkup("Verifies a signature against a public key.")
	ctx.initialState = false
	ctx.fileMode = false
	text, _ := ctx.notePad.GetText(ctx.notePad.GetStartIter(), ctx.notePad.GetEndIter(), true)
	if ctx.loadedKey != nil {
		pubKeyObj := ctx.loadedKey                                //loaded key should maybe be keyoobj with E521 for public key instead of x/y
		keyX, _ := big.NewInt(0).SetString(pubKeyObj.PubKeyX, 10) //refactor
		keyY, _ := big.NewInt(0).SetString(pubKeyObj.PubKeyY, 10) //refactor
		key := NewE521XY(*keyX, *keyY)
		signatureBytes, err := parseSOAP(&text, signatureBegin, signatureEnd)
		if err != nil {
			ctx.updateStatus("error parsing signature")
		} else {
			signature, err2 := decodeSignature(signatureBytes)
			if err != nil || err2 != nil {
				ctx.updateStatus("unable to parse signature")
			} else {
				result := verify(key, signature, &signature.M)
				if result {
					ctx.updateStatus("good signature from key " + ctx.loadedKey.Id)
				} else {
					ctx.updateStatus("unable to verify signature")
				}
			}
		}
	} else {
		ctx.updateStatus("no key selected")
	}
}
