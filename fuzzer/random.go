package fuzzer

import (
	"math/big"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	"github.com/MariusVanDerWijden/FuzzyVM/generator"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func randomTxData(f *filler.Filler, nonce uint64, gasFeeCap, gasTipCap *big.Int) types.TxData {
	to := randomAddr(f)
	code := randomCode(f)
	value := randomValue(f)
	gasLimit := TX_GAS_LIMIT

	legacyContractCreation := &types.LegacyTx{
		Nonce:    nonce,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasFeeCap,
		Data:     code,
	}

	legacyTransaction := &types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasFeeCap,
	}

	eip1559ContractCreation := &types.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        nil,
		Value:     value,
		Data:      code,
	}

	eip1559Transaction := &types.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &to,
		Value:     value,
		Data:      code,
	}

	switch f.Byte() % byte(4) {
	case 0:
		// Legacy contract creation
		if ALLOW_LEGACY_TXS {
			return legacyContractCreation
		} else {
			return eip1559ContractCreation
		}
	case 1:
		// Legacy transaction
		if ALLOW_LEGACY_TXS {
			return legacyTransaction
		} else {
			return eip1559Transaction
		}
	case 2:
		// 1559 contract creation
		return eip1559ContractCreation
	case 3:
		// 1559 transaction
		return eip1559Transaction
	default:
		panic("unreachable")
	}
}

func randomCode(f *filler.Filler) []byte {
	_, code := generator.GenerateProgram(f)
	if len(code) > 128 {
		code = code[:128]
	}
	return code
}

func randomValue(f *filler.Filler) *big.Int {
	return f.BigInt16()
}

func randomAddr(f *filler.Filler) common.Address {
	return common.BytesToAddress(f.ByteSlice(20))
}
