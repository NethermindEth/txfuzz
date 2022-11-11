package fuzzer

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	"github.com/NethermindEth/tx-fuzz/logger"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
)

const (
	AIRDROP_TARGET_VALUE = 100
	AIRDROP_PERIOD       = 30 * time.Second
	TX_GAS_LIMIT         = uint64(300000) // about 100 txs to fill a 30 million gas limit block
	ALLOW_LEGACY_TXS     = false
)

var gasTipCap = common.Big1

type TxFuzzer struct {
	key     *ecdsa.PrivateKey
	client  *ethclient.Client
	chainId *big.Int

	cooldown  atomic.Value
	gasFeeCap atomic.Value
}

func NewFuzzer(rpcUrl string, key *ecdsa.PrivateKey) *TxFuzzer {
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		logger.Default().Fatalf("Could not connect to rpc '%v': %v", rpcUrl, err)
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		logger.Default().Fatalf("Could not get chainId from rpc: %v", err)
	}

	fuzzer := &TxFuzzer{
		key:     key,
		client:  client,
		chainId: chainId,
	}

	fuzzer.cooldown.Store(time.Second)
	fuzzer.gasFeeCap.Store(new(big.Int).Add(big.NewInt(params.InitialBaseFee), common.Big1))

	return fuzzer
}

func (fuzzer *TxFuzzer) Fuzz(randomSeed int64, mnemonic string, startIdx, endIdx uint32) {
	logger.Default().Printf("Fuzzing using random seed %v\n", randomSeed)
	random := rand.New(rand.NewSource(randomSeed))
	keys, addrs := deriveAccounts(mnemonic, startIdx, endIdx)

	fuzzer.StartWatching(addrs)
	fuzzer.ScheduleAirdrops(addrs)

	var wg sync.WaitGroup
	wg.Add(len(keys))
	for i, key := range keys {
		// Set up the randomness
		randomBytes := make([]byte, 10000)
		random.Read(randomBytes)
		f := filler.NewFiller(randomBytes)
		go func(key *ecdsa.PrivateKey, addr common.Address, f *filler.Filler) {
			fuzzer.StartFuzzingFrom(key, addr, f)
			wg.Done()
		}(key, addrs[i], f)
	}
	wg.Wait()
}

func (fuzzer *TxFuzzer) StartFuzzingFrom(key *ecdsa.PrivateKey, addr common.Address, f *filler.Filler) {
	nonce, err := fuzzer.client.PendingNonceAt(context.Background(), addr)
	if err != nil {
		logger.Verbose().Printf("Could not get nonce: %v\n", err)
	}

	for {
		txData := randomTxData(f, nonce, fuzzer.GasFeeCap(), gasTipCap)
		signer := types.NewLondonSigner(fuzzer.chainId)
		signedTx, err := types.SignNewTx(key, signer, txData)
		if err != nil {
			logger.Default().Fatalf("Could not sign new transaction: %v\n", err)
		}

		if err = fuzzer.sendTx(signedTx); err != nil {
			logger.Verbose().Printf("Could not send tx{sender: %v, nonce: %v}: %v\n", addr, signedTx.Nonce(), err)
			// sometimes tx sending fails because of nonce gap, most likely because some transactions
			// that were in the pool at the moment of asking for nonce to the node were invalidated
			// (probably because of baseFee increase and new txs being submitted)
			rectifiedNonce, err := fuzzer.client.PendingNonceAt(context.Background(), addr)
			if err != nil {
				logger.Default().Fatalf("Could not get nonce: %v\n", err)
			}
			nonce = rectifiedNonce
			continue
		}

		logger.Verbose().Printf("Sent tx{sender: %v, nonce: %v}\n", addr, signedTx.Nonce())
		cooldown := fuzzer.Cooldown()
		if cooldown > 10*time.Millisecond {
			time.Sleep(cooldown)
		}
		nonce++
	}
}

func (fuzzer *TxFuzzer) ScheduleAirdrops(addrs []common.Address) {
	fuzzer.doAirdrop(addrs)
	go func() {
		for range time.Tick(AIRDROP_PERIOD) {
			fuzzer.doAirdrop(addrs)
		}
	}()
}

func (fuzzer *TxFuzzer) doAirdrop(addrs []common.Address) {
	targetValue := new(big.Int).Mul(big.NewInt(AIRDROP_TARGET_VALUE), big.NewInt(params.Ether))
	logger.Verbose().Printf("Airdrop to get accounts back to %v wei\n", targetValue)

	var lastTx *types.Transaction
	for _, to := range addrs {
		balance, err := fuzzer.client.PendingBalanceAt(context.Background(), to)
		if err != nil {
			logger.Default().Fatalf("Could not get pending balance for addr %v: %v\n", to, err)
		}
		value := new(big.Int).Sub(targetValue, balance)
		if value.Cmp(big.NewInt(0)) <= 0 {
			logger.Verbose().Printf("Addr %v already has %v wei\n", to, balance)
			continue
		}
		logger.Verbose().Printf("Addr %v will be airdropped %v wei\n", to.Hex(), value)

		nonce, err := fuzzer.client.PendingNonceAt(context.Background(), crypto.PubkeyToAddress(fuzzer.key.PublicKey))
		if err != nil {
			logger.Default().Fatalf("Could not get pending nonce for fuzzer: %v\n", err)
		}
		txData := types.DynamicFeeTx{
			ChainID:   fuzzer.chainId,
			Nonce:     nonce,
			GasTipCap: new(big.Int).Mul(gasTipCap, common.Big2),
			GasFeeCap: new(big.Int).Mul(fuzzer.GasFeeCap(), common.Big2),
			Gas:       params.TxGas,
			To:        &to,
			Value:     value,
		}
		signedTx, err := types.SignNewTx(fuzzer.key, types.LatestSignerForChainID(fuzzer.chainId), &txData)
		if err != nil {
			logger.Default().Fatalf("Couldn't sign transaction for airdrop: %v\n", err)
		}
		for err = fuzzer.sendTx(signedTx); err != nil; err = fuzzer.sendTx(signedTx) {
			logger.Default().Printf("Couldn't send airdrop transaction: %v\n", err)
			time.Sleep(5 * time.Second)
		}
		lastTx = signedTx
	}
	if lastTx == nil {
		logger.Default().Printf("Airdrop finished without airdropping anything")
		return
	}
	// Wait for the last transaction to be mined
	logger.Default().Println("Waiting for airdrop")
	bind.WaitMined(context.Background(), fuzzer.client, lastTx)
	logger.Default().Println("Airdrop succesful")
}

func (fuzzer *TxFuzzer) sendTx(signedTx *types.Transaction) error {
	return fuzzer.client.SendTransaction(context.Background(), signedTx)
}
