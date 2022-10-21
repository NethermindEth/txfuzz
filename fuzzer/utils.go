package fuzzer

import (
	"crypto/ecdsa"

	"github.com/NethermindEth/tx-fuzz/logger"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func deriveAccounts(mnemonic string, startIdx, endIdx uint32) ([]*ecdsa.PrivateKey, []common.Address) {
	keys := make([]*ecdsa.PrivateKey, 0, endIdx-startIdx)
	addrs := make([]common.Address, 0, endIdx-startIdx)

	masterKey, err := bip32.NewMasterKey(bip39.NewSeed(mnemonic, ""))
	if err != nil {
		logger.Default().Fatalf("Could not create new master key from mnemonic: %v\n", err)
	}

	for _, edge := range accounts.DefaultRootDerivationPath {
		masterKey, err = masterKey.NewChildKey(edge)
		if err != nil {
			logger.Default().Fatalf("Could not derive key: %v\n", err)
		}
	}

	for idx := startIdx; idx < endIdx; idx++ {
		derivedKey, err := masterKey.NewChildKey(idx)
		if err != nil {
			logger.Default().Fatalf("Could not derive key for idx %v: %v\n", idx, err)
		}

		pvKey := crypto.ToECDSAUnsafe(derivedKey.Key)
		addr := crypto.PubkeyToAddress(pvKey.PublicKey)

		keys = append(keys, pvKey)
		addrs = append(addrs, addr)

		logger.Verbose().Printf("Succesfully enerated account %v from mnemonic index %v\n", addr, idx)
	}
	logger.Default().Printf("Succesfully generated accounts from mnemonic range %v..%v\n", startIdx, endIdx)

	return keys, addrs
}
