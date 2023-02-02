package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	appparams "github.com/osmosis-labs/osmosis/v14/app/params"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/osmosis-labs/osmosis/v14/app/params"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	tmcmds "github.com/tendermint/tendermint/cmd/tendermint/commands"
	tmcli "github.com/tendermint/tendermint/libs/cli"
	"github.com/tendermint/tendermint/libs/log"
	dbm "github.com/tendermint/tm-db"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/server"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/snapshots"
	snapshottypes "github.com/cosmos/cosmos-sdk/snapshots/types"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"

	"github.com/CosmWasm/wasmd/x/wasm"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	osmosis "github.com/osmosis-labs/osmosis/v14/app"
)

// NewRootCmd creates a new root command for simd. It is called once in the
// main function.
func NewRootCmd() (*cobra.Command, params.EncodingConfig) {
	encodingConfig := osmosis.MakeEncodingConfig()
	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Marshaler).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithInput(os.Stdin).
		WithAccountRetriever(types.AccountRetriever{}).
		WithBroadcastMode(flags.BroadcastBlock).
		WithHomeDir(osmosis.DefaultNodeHome).
		WithViper("OSMOSIS")

	rootCmd := &cobra.Command{
		Use:   "osmosisd",
		Short: "Start osmosis app",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			initClientCtx, err := client.ReadPersistentCommandFlags(initClientCtx, cmd.Flags())
			if err != nil {
				return err
			}
			initClientCtx, err = config.ReadFromClientConfig(initClientCtx)
			if err != nil {
				return err
			}

			if err := client.SetCmdClientContextHandler(initClientCtx, cmd); err != nil {
				return err
			}
			customAppTemplate, customAppConfig := initAppConfig()
			return server.InterceptConfigsPreRunHandler(cmd, customAppTemplate, customAppConfig)
		},
		SilenceUsage: true,
	}

	initRootCmd(rootCmd, encodingConfig)

	return rootCmd, encodingConfig
}

// initAppConfig helps to override default appConfig template and configs.
// return "", nil if no custom configuration is required for the application.
func initAppConfig() (string, interface{}) {
	type OsmosisMempoolConfig struct {
		ArbitrageMinGasPrice string `mapstructure:"arbitrage-min-gas-fee"`
	}

	type CustomAppConfig struct {
		serverconfig.Config

		OsmosisMempoolConfig OsmosisMempoolConfig `mapstructure:"osmosis-mempool"`
	}

	// Optionally allow the chain developer to overwrite the SDK's default
	// server config.
	srvCfg := serverconfig.DefaultConfig()
	srvCfg.API.Enable = true
	srvCfg.StateSync.SnapshotInterval = 1500
	srvCfg.StateSync.SnapshotKeepRecent = 2
	srvCfg.MinGasPrices = "0uosmo"

	// 128MB IAVL cache
	srvCfg.IAVLCacheSize = 781250

	memCfg := OsmosisMempoolConfig{ArbitrageMinGasPrice: "0.01"}

	OsmosisAppCfg := CustomAppConfig{Config: *srvCfg, OsmosisMempoolConfig: memCfg}

	OsmosisAppTemplate := serverconfig.DefaultConfigTemplate + `
###############################################################################
###                      Osmosis Mempool Configuration                      ###
###############################################################################

[osmosis-mempool]
# This is the max allowed gas any tx. 
# This is only for local mempool purposes, and thus	is only ran on check tx.
max-gas-wanted-per-tx = "25000000"

# This is the minimum gas fee any arbitrage tx should have, denominated in uosmo per gas
# Default value of ".005" then means that a tx with 1 million gas costs (.005 uosmo/gas) * 1_000_000 gas = .005 osmo
arbitrage-min-gas-fee = ".005"

# This is the minimum gas fee any tx with high gas demand should have, denominated in uosmo per gas
# Default value of ".0025" then means that a tx with 1 million gas costs (.0025 uosmo/gas) * 1_000_000 gas = .0025 osmo
min-gas-price-for-high-gas-tx = ".0025"
`

	return OsmosisAppTemplate, OsmosisAppCfg
}

// initRootCmd initializes root commands when creating a new root command for simd.
func initRootCmd(rootCmd *cobra.Command, encodingConfig params.EncodingConfig) {
	cfg := sdk.GetConfig()
	cfg.Seal()

	debugCmd := debug.Cmd()
	debugCmd.AddCommand(ConvertBech32Cmd())

	rootCmd.AddCommand(
		// genutilcli.InitCmd(osmosis.ModuleBasics, osmosis.DefaultNodeHome),
		forceprune(),
		InitCmd(osmosis.ModuleBasics, osmosis.DefaultNodeHome),
		genutilcli.CollectGenTxsCmd(banktypes.GenesisBalancesIterator{}, osmosis.DefaultNodeHome),
		genutilcli.MigrateGenesisCmd(),
		ExportDeriveBalancesCmd(),
		StakedToCSVCmd(),
		AddGenesisAccountCmd(osmosis.DefaultNodeHome),
		AddGenesisWasmMsgCmd(osmosis.DefaultNodeHome),
		genutilcli.GenTxCmd(osmosis.ModuleBasics, encodingConfig.TxConfig, banktypes.GenesisBalancesIterator{}, osmosis.DefaultNodeHome),
		genutilcli.ValidateGenesisCmd(osmosis.ModuleBasics),
		PrepareGenesisCmd(osmosis.DefaultNodeHome, osmosis.ModuleBasics),
		tmcli.NewCompletionCmd(rootCmd, true),
		testnetCmd(osmosis.ModuleBasics, banktypes.GenesisBalancesIterator{}),
		tmcmds.RollbackStateCmd,
		debugCmd,
		config.Cmd(),
	)

	server.AddCommands(rootCmd, osmosis.DefaultNodeHome, newApp, createOsmosisAppAndExport, addModuleInitFlags)

	// add keybase, auxiliary RPC, query, and tx child commands
	rootCmd.AddCommand(
		rpc.StatusCommand(),
		queryCommand(),
		txCommand(),
		keys.Commands(osmosis.DefaultNodeHome),
	)
	// add rosetta
	rootCmd.AddCommand(server.RosettaCommand(encodingConfig.InterfaceRegistry, encodingConfig.Marshaler))
}

func addModuleInitFlags(startCmd *cobra.Command) {
	crisis.AddModuleInitFlags(startCmd)
	wasm.AddModuleInitFlags(startCmd)
}

// queryCommand adds transaction and account querying commands.
func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetAccountCmd(),
		rpc.ValidatorCommand(),
		rpc.BlockCommand(),
		authcmd.QueryTxsByEventsCmd(),
		authcmd.QueryTxCmd(),
	)

	osmosis.ModuleBasics.AddQueryCommands(cmd)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

// txCommand adds transaction signing, encoding / decoding, and broadcasting commands.
func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetValidateSignaturesCommand(),
		flags.LineBreak,
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		NewMultiSendCmd(),
	)

	osmosis.ModuleBasics.AddTxCommands(cmd)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

// newApp initializes and returns a new Osmosis app.
func newApp(logger log.Logger, db dbm.DB, traceStore io.Writer, appOpts servertypes.AppOptions) servertypes.Application {
	var cache sdk.MultiStorePersistentCache

	if cast.ToBool(appOpts.Get(server.FlagInterBlockCache)) {
		cache = store.NewCommitKVStoreCacheManager()
	}

	skipUpgradeHeights := make(map[int64]bool)
	for _, h := range cast.ToIntSlice(appOpts.Get(server.FlagUnsafeSkipUpgrades)) {
		skipUpgradeHeights[int64(h)] = true
	}

	pruningOpts, err := server.GetPruningOptionsFromFlags(appOpts)
	if err != nil {
		panic(err)
	}

	snapshotDir := filepath.Join(cast.ToString(appOpts.Get(flags.FlagHome)), "data", "snapshots")
	snapshotDB, err := sdk.NewLevelDB("metadata", snapshotDir)
	if err != nil {
		panic(err)
	}
	snapshotStore, err := snapshots.NewStore(snapshotDB, snapshotDir)
	if err != nil {
		panic(err)
	}

	var wasmOpts []wasm.Option
	if cast.ToBool(appOpts.Get("telemetry.enabled")) {
		wasmOpts = append(wasmOpts, wasmkeeper.WithVMCacheMetrics(prometheus.DefaultRegisterer))
	}

	return osmosis.NewOsmosisApp(
		logger, db, traceStore, true, skipUpgradeHeights,
		cast.ToString(appOpts.Get(flags.FlagHome)),
		cast.ToUint(appOpts.Get(server.FlagInvCheckPeriod)),
		appOpts,
		osmosis.GetWasmEnabledProposals(),
		wasmOpts,
		baseapp.SetPruning(pruningOpts),
		baseapp.SetMinGasPrices(cast.ToString(appOpts.Get(server.FlagMinGasPrices))),
		baseapp.SetMinRetainBlocks(cast.ToUint64(appOpts.Get(server.FlagMinRetainBlocks))),
		baseapp.SetHaltHeight(cast.ToUint64(appOpts.Get(server.FlagHaltHeight))),
		baseapp.SetHaltTime(cast.ToUint64(appOpts.Get(server.FlagHaltTime))),
		baseapp.SetMinRetainBlocks(cast.ToUint64(appOpts.Get(server.FlagMinRetainBlocks))),
		baseapp.SetInterBlockCache(cache),
		baseapp.SetTrace(cast.ToBool(appOpts.Get(server.FlagTrace))),
		baseapp.SetIndexEvents(cast.ToStringSlice(appOpts.Get(server.FlagIndexEvents))),
		baseapp.SetSnapshot(snapshotStore, snapshottypes.NewSnapshotOptions(cast.ToUint64(appOpts.Get(server.FlagStateSyncSnapshotInterval)), cast.ToUint32(appOpts.Get(server.FlagStateSyncSnapshotKeepRecent)))),
	)
}

// createOsmosisAppAndExport creates and exports the new Osmosis app, returns the state of the new Osmosis app for a genesis file.
func createOsmosisAppAndExport(
	logger log.Logger, db dbm.DB, traceStore io.Writer, height int64, forZeroHeight bool, jailWhiteList []string,
	appOpts servertypes.AppOptions, modulesToExport []string,
) (servertypes.ExportedApp, error) {
	encCfg := osmosis.MakeEncodingConfig() // Ideally, we would reuse the one created by NewRootCmd.
	encCfg.Marshaler = codec.NewProtoCodec(encCfg.InterfaceRegistry)
	loadLatest := height == -1
	homeDir := cast.ToString(appOpts.Get(flags.FlagHome))
	app := osmosis.NewOsmosisApp(logger, db, traceStore, loadLatest, map[int64]bool{}, homeDir, 0, appOpts, osmosis.GetWasmEnabledProposals(), osmosis.EmptyWasmOpts)

	if !loadLatest {
		if err := app.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	}

	return app.ExportAppStateAndValidators(forZeroHeight, jailWhiteList, modulesToExport)
}

func parseCSV(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		panic(err)
	}

	return records
}

// NewMultiSendCmd returns a CLI command for multi-send
func NewMultiSendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "multi-send [csv_file] [denom] [startIndex] [threshold]",
		Short:   "Execute multisend based on csv file",
		Example: `osmosisd tx multi-send "./airdrop.csv" acnto 0 100 --from=mykey --keyring-backend=test`,
		Args:    cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			sendMsgs := []banktypes.MsgSend{}
			amountRecords := parseCSV(args[0])

			for _, line := range amountRecords[1:] {
				addr, amountStr := line[0], line[1]

				_, bz, err := bech32.DecodeAndConvert(addr)
				if err != nil {
					return err
				}

				osmoAddr, err := bech32.ConvertAndEncode(appparams.Bech32PrefixAccAddr, bz)
				if err != nil {
					return err
				}
				amountDec := sdk.MustNewDecFromStr(amountStr)
				decimalReduction := sdk.NewInt(1000_000_000).Mul(sdk.NewInt(1000_000_000)) // 10^18
				amount := amountDec.Mul(sdk.NewDecFromBigInt(decimalReduction.BigInt())).TruncateInt()

				msg := banktypes.MsgSend{
					FromAddress: clientCtx.FromAddress.String(),
					ToAddress:   osmoAddr,
					Amount:      sdk.Coins{sdk.NewCoin(args[1], amount)},
				}
				sendMsgs = append(sendMsgs, msg)
			}

			startIndex, err := strconv.Atoi(args[2])
			if err != nil {
				return err
			}
			threshold, err := strconv.Atoi(args[3])
			if err != nil {
				return err
			}

			msgs := []sdk.Msg{}
			for index, msg := range sendMsgs {
				if index < startIndex {
					continue
				}
				msgs = append(msgs, &banktypes.MsgSend{
					FromAddress: msg.FromAddress,
					ToAddress:   msg.ToAddress,
					Amount:      msg.Amount,
				})
				if len(msgs) >= threshold || index+1 == len(sendMsgs) {
					err := tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msgs...)
					if err != nil {
						return err
					}
					fmt.Printf("executed batch %d/%d\n", index+1, len(sendMsgs))
					msgs = []sdk.Msg{}
				}
			}
			fmt.Println("finalized batch execution")

			return nil
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
