package main

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/NethermindEth/tx-fuzz/fuzzer"
	"github.com/NethermindEth/tx-fuzz/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	if len(os.Args) == 1 {
		log.Fatalf("%v <rpc-url> <hex-formatted-pvkey> <mnemonic> <start..end> [<hex-formatted-seed>] [<bool-verbose>]\n", os.Args[0])
	}

	if len(os.Args) < 5 || len(os.Args) > 7 {
		log.Fatalln("invalid amount of args, need from 5 to 7 args")
	}

	url := os.Args[1]
	key := crypto.ToECDSAUnsafe(common.FromHex(os.Args[2]))
	mnemonic := os.Args[3]

	startIdxStr, endIdxStr, isRange := strings.Cut(os.Args[4], "..")
	startIdx, err := strconv.Atoi(startIdxStr)
	if err != nil {
		log.Default().Fatalf("Couldn't parse mnemonic range start: %v\n", err)
	}
	endIdx := startIdx + 1
	if isRange {
		endIdx, err = strconv.Atoi(endIdxStr)
		if err != nil {
			log.Default().Fatalf("Couldn't parse mnemonic range end: %v\n", err)
		}
	}

	var seed int64
	if len(os.Args) > 5 {
		log.Default().Println("Using provided seed")
		a := common.LeftPadBytes(common.FromHex(os.Args[5]), 8)
		seed = int64(binary.BigEndian.Uint64(a))
	} else {
		log.Default().Println("No seed provided, creating one")
		rnd := make([]byte, 8)
		rand.Read(rnd)
		seed = int64(binary.BigEndian.Uint64(rnd))
	}

	if len(os.Args) > 6 {
		verbose, err := strconv.ParseBool(os.Args[6])
		if err != nil {
			logger.Default().Fatalf("Couldn't parse verbosity flag: %v\n", err)
		}
		if verbose {
			logger.SetVerbosity(2)
		}
	}

	fuzzer := fuzzer.NewFuzzer(url, key)
	fuzzer.Fuzz(seed, mnemonic, uint32(startIdx), uint32(endIdx))
}
