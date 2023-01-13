#!/bin/bash

# This script compiles a list of .go files and runs the executable after compilation

# Loop through the list of files
	# Compile the file
# go build view.go model.go sponge.go keccakf.go utilities.go cSHAKE.go dialogs.go controller.go keyTable.go E521.go message_formatter.go E521Tests.go secp256k1_sig.go
go build ecdsa.go
# # Run the executable
 ./ecdsa