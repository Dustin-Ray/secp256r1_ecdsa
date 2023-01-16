#!/bin/bash
go build run_tests.go secp256r1_ecdsa.go E222.go E222Tests.go E222_schnorr.go secp256r1_sig_Schnorr.go
# # Run the executable
./run_tests