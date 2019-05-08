package main

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/keyproof/primeproofs"

	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"time"
)

type StepStartMessage struct {
	desc          string
	intermediates int
}
type StepDoneMessage struct{}
type TickMessage struct{}
type QuitMessage struct{}
type FinishMessage struct{}
type SetFinalMessage struct {
	message string
}

type LogFollower struct {
	StepStartEvents chan<- StepStartMessage
	StepDoneEvents  chan<- StepDoneMessage
	TickEvents      chan<- TickMessage
	QuitEvents      chan<- QuitMessage
	FinalEvents     chan<- SetFinalMessage
	Finished        <-chan FinishMessage
}

func (l *LogFollower) StepStart(desc string, intermediates int) {
	l.StepStartEvents <- StepStartMessage{desc, intermediates}
}

func (l *LogFollower) StepDone() {
	l.StepDoneEvents <- StepDoneMessage{}
}

func (l *LogFollower) Tick() {
	l.TickEvents <- TickMessage{}
}

func (l *LogFollower) Quit() {
	l.QuitEvents <- QuitMessage{}
}

func PrintStatus(status string, count, limit int, done bool) {
	var tail string
	if done {
		tail = "done"
	} else if limit > 0 {
		tail = fmt.Sprintf("%v/%v", count, limit)
	} else {
		tail = ""
	}

	tlen := len(tail)
	if tlen == 0 {
		tlen = 4
	}

	fmt.Printf("\r%s", status)
	for i := 0; i < 60-len(status)-tlen; i++ {
		fmt.Printf(".")
	}
	fmt.Printf("%s", tail)
}

func StartLogFollower() *LogFollower {
	var result = new(LogFollower)

	starts := make(chan StepStartMessage)
	dones := make(chan StepDoneMessage)
	ticks := make(chan TickMessage)
	quit := make(chan QuitMessage)
	finished := make(chan FinishMessage)
	finalmessage := make(chan SetFinalMessage)

	result.StepStartEvents = starts
	result.StepDoneEvents = dones
	result.TickEvents = ticks
	result.QuitEvents = quit
	result.Finished = finished
	result.FinalEvents = finalmessage

	go func() {
		doneMissing := 0
		curStatus := ""
		curCount := 0
		curLimit := 0
		curDone := true
		finalMessage := ""
		ticker := time.NewTicker(time.Second / 4)
		defer ticker.Stop()

		for {
			select {
			case <-ticks:
				curCount++
			case <-dones:
				if doneMissing > 0 {
					doneMissing--
					continue // Swallow quietly
				} else {
					curDone = true
					PrintStatus(curStatus, curCount, curLimit, true)
					fmt.Printf("\n")
				}
			case stepstart := <-starts:
				if !curDone {
					PrintStatus(curStatus, curCount, curLimit, true)
					fmt.Printf("\n")
					doneMissing++
				}
				curDone = false
				curCount = 0
				curLimit = stepstart.intermediates
				curStatus = stepstart.desc
			case messageevent := <-finalmessage:
				finalMessage = messageevent.message
			case <-quit:
				if finalMessage != "" {
					fmt.Printf("%s\n", finalMessage)
				}
				finished <- FinishMessage{}
				return
			case <-ticker.C:
				if !curDone {
					PrintStatus(curStatus, curCount, curLimit, false)
				}
			}
		}
	}()

	primeproofs.Follower = result

	return result
}

func printHelp() {
	fmt.Printf("Usage: keyproof [action] [keyfile(s)] [prooffile]\n")
	fmt.Printf("Possible actions: buildproof, verify\n")
}

func buildProof(pkfilename, skfilename, prooffilename string) {
	// Try to read public key
	pk, err := gabi.NewPublicKeyFromFile(pkfilename)
	if err != nil {
		fmt.Printf("Error reading in public key: %s", err.Error())
		return
	}

	// Try to read private key
	sk, err := gabi.NewPrivateKeyFromFile(skfilename)
	if err != nil {
		fmt.Printf("Error reading in private key: %s\n", err.Error())
		return
	}

	// Validate that they match
	if pk.N.Cmp(new(big.Int).Mul(sk.P, sk.Q)) != 0 {
		fmt.Printf("Private and public key do not match\n")
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
	s := primeproofs.NewValidKeyProofStructure(pk.N, pk.Z, pk.S, pk.R)
	proof := s.BuildProof(sk.PPrime, sk.QPrime)

	// And write it to file
	follower.StepStart("Writing proof", 0)
	proofEncoder := json.NewEncoder(proofFile)
	proofEncoder.Encode(proof)
	follower.StepDone()
}

func verifyProof(pkfilename, prooffilename string) {
	// Try to read public key
	pk, err := gabi.NewPublicKeyFromFile(pkfilename)
	if err != nil {
		fmt.Printf("Error reading in public key: %s\n", err.Error())
		return
	}

	// Try to read proof
	follower.StepStart("Reading proofdata", 0)
	proofFile, err := os.Open(prooffilename)
	if err != nil {
		follower.StepDone()
		follower.FinalEvents <- SetFinalMessage{fmt.Sprintf("Error opening proof: %s\n", err.Error())}
		return
	}
	defer proofFile.Close()
	proofDecoder := json.NewDecoder(proofFile)
	var proof primeproofs.ValidKeyProof
	err = proofDecoder.Decode(&proof)
	if err != nil {
		follower.StepDone()
		follower.FinalEvents <- SetFinalMessage{fmt.Sprintf("Error reading in proof data: %s\n", err.Error())}
		return
	}
	follower.StepDone()

	// Construct proof structure
	s := primeproofs.NewValidKeyProofStructure(pk.N, pk.Z, pk.S, pk.R)

	// And use it to validate the proof
	if !s.VerifyProof(proof) {
		follower.FinalEvents <- SetFinalMessage{"Proof is INVALID!"}
	} else {
		follower.FinalEvents <- SetFinalMessage{"Proof is valid"}
	}
}

var follower *LogFollower

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func main() {
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if len(flag.Args()) < 3 {
		printHelp()
		return
	}

	follower = StartLogFollower()
	defer func() {
		follower.QuitEvents <- QuitMessage{}
		<-follower.Finished
	}()

	if flag.Arg(0) == "buildproof" {
		if len(flag.Args()) != 4 {
			printHelp()
			return
		}
		buildProof(flag.Arg(1), flag.Arg(2), flag.Arg(3))
		return
	}
	if flag.Arg(0) == "verify" {
		if len(flag.Args()) != 3 {
			printHelp()
			return
		}
		verifyProof(flag.Arg(1), flag.Arg(2))
		return
	}

	printHelp()
}
