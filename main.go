package main

import "github.com/privacybydesign/keyproof/primeproofs"
import "github.com/mhe/gabi/big"
import "github.com/mhe/gabi"
import "encoding/json"
import "fmt"
import "os"

func printHelp() {
	fmt.Printf("Usage: keyproof [action] [keyfile] [prooffile]\n")
	fmt.Printf("Possible actions: buildproof, verify\n")
}

func buildProof(skfilename, prooffilename string) {
	// Try to read private key
	sk, err := gabi.NewPrivateKeyFromFile(skfilename)
	if err != nil {
		fmt.Printf("Error reading in private key: %s\n", err.Error())
		return
	}

	// Validate that it is amenable
	ConstEight := big.NewInt(8)
	ConstOne := big.NewInt(1)
	PMod := new(big.Int).Mod(sk.P, ConstEight)
	QMod := new(big.Int).Mod(sk.Q, ConstEight)
	PPrimeMod := new(big.Int).Mod(sk.PPrime, ConstEight)
	QPrimeMod := new(big.Int).Mod(sk.QPrime, ConstEight)
	if PMod.Cmp(ConstOne) == 0 || QMod.Cmp(ConstOne) == 0 ||
		PPrimeMod.Cmp(ConstOne) == 0 || QPrimeMod.Cmp(ConstOne) == 0 ||
		PMod.Cmp(QMod) == 0 || PPrimeMod.Cmp(QPrimeMod) == 0 {
		fmt.Printf("Private key not amenable to proving\n")
		return
	}

	// Open proof file for writing
	proofFile, err := os.Create(prooffilename)
	if err != nil {
		fmt.Printf("Error opening proof file for writing: %s\n", err.Error())
		return
	}
	defer proofFile.Close()

	// Build the proof
	N := new(big.Int).Mul(sk.P, sk.Q)
	s := primeproofs.NewSafePrimeProofStructure(N)
	proof := s.BuildProof(sk.PPrime, sk.QPrime)

	// And write it to file
	proofEncoder := json.NewEncoder(proofFile)
	proofEncoder.Encode(proof)
}

func verifyProof(pkfilename, prooffilename string) {
	// Try to read proof
	proofFile, err := os.Open(prooffilename)
	if err != nil {
		fmt.Printf("Error opening proof: %s\n", err.Error())
		return
	}
	defer proofFile.Close()
	proofDecoder := json.NewDecoder(proofFile)
	var proof primeproofs.SafePrimeProof
	err = proofDecoder.Decode(&proof)
	if err != nil {
		fmt.Printf("Error reading in proof data: %s\n", err.Error())
		return
	}

	// Try to read public key
	pk, err := gabi.NewPublicKeyFromFile(pkfilename)
	if err != nil {
		fmt.Printf("Error reading in public key: %s\n", err.Error())
		return
	}

	// Construct proof structure
	s := primeproofs.NewSafePrimeProofStructure(pk.N)

	// And use it to validate the proof
	if !s.VerifyProof(proof) {
		fmt.Printf("Proof is INVALID!\n")
	} else {
		fmt.Printf("Proof is valid\n")
	}
}

func main() {
	if len(os.Args) != 4 {
		printHelp()
		return
	}

	if os.Args[1] == "buildproof" {
		buildProof(os.Args[2], os.Args[3])
		return
	}
	if os.Args[1] == "verify" {
		verifyProof(os.Args[2], os.Args[3])
		return
	}

	printHelp()
}
