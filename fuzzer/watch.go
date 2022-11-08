package fuzzer

import (
	"context"
	"log"
	"math/big"
	"time"

	"github.com/NethermindEth/tx-fuzz/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

var fullBlockMaxCost = new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))

func (fuzzer *TxFuzzer) StartWatching(addrs []common.Address) {
	waitCh := make(chan struct{})

	signer := types.NewLondonSigner(fuzzer.chainId)
	watchedAddrs := make(map[common.Address]struct{})
	for _, addr := range addrs {
		watchedAddrs[addr] = struct{}{}
	}

	headCh := make(chan *types.Header)
	headSub, err := fuzzer.client.SubscribeNewHead(context.Background(), headCh)
	if err != nil {
		logger.Default().Fatalf("Could not subscribe to new heads: %v\n", err)
	}

	go func() {
		var (
			gasUsageHist [5]uint64
			gasUsageSum  uint64
			goingDown    bool
		)
		missingHist := len(gasUsageHist)
		for {
			select {
			case err := <-headSub.Err():
				logger.Default().Fatalf("NewHead subscription error: %v\n", err)
			case header := <-headCh:
				block, err := fuzzer.client.BlockByHash(context.Background(), header.Hash())
				if err != nil {
					logger.Default().Fatalf("Could not get block %v from rpc: %v\n", header.Number, err)
				}

				if missingHist > 0 {
					missingHist--
				}

				watchedTxsCount := 0
				for _, tx := range block.Transactions() {
					if sender, err := types.Sender(signer, tx); err != nil {
						logger.Default().Fatalf("Could not recover sender from tx: %v\n", err)
					} else if _, isFuzzerAddr := watchedAddrs[sender]; isFuzzerAddr {
						watchedTxsCount++
						logger.Verbose().Printf("Included tx{sender: %v, nonce: %v} in block %v\n", sender, tx.Nonce(), block.NumberU64())
					}
				}

				// fix next gas fee accordingly
				gasFeeCap := misc.CalcBaseFee(&params.ChainConfig{LondonBlock: common.Big0}, block.Header())
				gasFeeCap.Add(gasFeeCap, common.Big1)
				gasFeeCap.Mul(gasFeeCap, big.NewInt(110))
				gasFeeCap.Div(gasFeeCap, big.NewInt(100))
				fuzzer.gasFeeCap.Store(gasFeeCap)

				if new(big.Int).Mul(gasFeeCap, new(big.Int).SetUint64(block.GasLimit())).Cmp(fullBlockMaxCost) > 0 {
					goingDown = true
				} else if goingDown && gasFeeCap.Cmp(big.NewInt(500)) < 0 {
					goingDown = false
				}

				// fix cooldown accordingly
				cooldown := fuzzer.Cooldown()
				gasUsage := 100 * block.GasUsed() / block.GasLimit()
				gasUsageIdx := block.NumberU64() % uint64(len(gasUsageHist))
				gasUsageSum -= gasUsageHist[gasUsageIdx]
				gasUsageHist[gasUsageIdx] = gasUsage
				gasUsageSum += gasUsageHist[gasUsageIdx]
				if missingHist <= 0 {
					gasUsageAvg := gasUsageSum / uint64(len(gasUsageHist))

					if goingDown {
						if gasUsageAvg > 40 {
							cooldown *= 2
							fuzzer.cooldown.Store(cooldown)
						}
					} else {
						if gasUsageAvg < 70 {
							cooldown = cooldown/2 + 1
							fuzzer.cooldown.Store(cooldown)
						}
					}
				}

				log.Default().Printf("Included %v transaction in block %v - block gas usage was %v percent - sending transaction every %v\n", watchedTxsCount, block.NumberU64(), gasUsage, cooldown)

				if waitCh != nil {
					close(waitCh)
					waitCh = nil
				}
			}
		}
	}()

	<-waitCh
}

func (fuzzer *TxFuzzer) GasFeeCap() *big.Int {
	// return fuzzer.gasFeeCap.Load().(*big.Int)
	return new(big.Int).Div(
		new(big.Int).Mul(big.NewInt(AIRDROP_TARGET_VALUE/3), big.NewInt(params.Ether)),
		new(big.Int).SetUint64(TX_GAS_LIMIT),
	)
}

func (fuzzer *TxFuzzer) Cooldown() time.Duration {
	return fuzzer.cooldown.Load().(time.Duration)
}
