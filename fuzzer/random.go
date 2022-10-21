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
	gasLimit := f.GasInt().Uint64()

	switch f.Byte() % byte(4) {
	case 0:
		// Legacy contract creation
		return &types.LegacyTx{
			Nonce:    nonce,
			Value:    value,
			Gas:      gasLimit,
			GasPrice: gasFeeCap,
			Data:     code,
		}
	case 1:
		// Legacy transaction
		return &types.LegacyTx{
			Nonce:    nonce,
			To:       &to,
			Value:    value,
			Gas:      gasLimit,
			GasPrice: gasFeeCap,
		}
	case 2:
		// 1559 contract creation
		return &types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        nil,
			Value:     value,
			Data:      code,
		}
	case 3:
		// 1559 transaction
		return &types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     value,
			Data:      code,
		}
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
