import
  os, options, strformat,
  confutils/defs, chronicles/options as chroniclesOptions,
  spec/[crypto, datatypes], time, version

export
  defs, enabledLogLevel

const
  DEFAULT_NETWORK* {.strdefine.} = "testnet0"

type
  ValidatorKeyPath* = TypedInputFile[ValidatorPrivKey, Txt, "privkey"]

  StartUpCommand* = enum
    noCommand
    importValidator
    createTestnet
    updateTestnet

  GenesisType* = enum
    eth1
    snapshot
    quickStart

  BeaconNodeConf* = object
    logLevel* {.
      desc: "Sets the log level",
      defaultValue: enabledLogLevel.}: LogLevel

    network* {.
      desc: "The network Nimbus should connect to. " &
            "Possible values: testnet0, testnet1, mainnet, custom-network.json"
      longform: "network"
      shortform: "n"
      defaultValue: DEFAULT_NETWORK .}: string

    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data."
      shortform: "d"
      defaultValue: config.defaultDataDir().}: OutDir

    case cmd* {.
      command
      defaultValue: noCommand.}: StartUpCommand

    of noCommand:
      nodename* {.
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be seleceted for each --dataDir folder"
        defaultValue: ""}: string

      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network."
        longform: "bootstrapNode"
        shortform: "b".}: seq[string]

      bootstrapNodesFile* {.
        desc: "Specifies a line-delimited file of bootsrap Ethereum network addresses"
        shortform: "f"
        defaultValue: "".}: InputFile

      tcpPort* {.
        desc: "TCP listening port"
        defaultValue: defaultPort(config) .}: int

      udpPort* {.
        desc: "UDP listening port",
        defaultValue: defaultPort(config) .}: int

      nat* {.
        desc: "Specify method to use for determining public address. Must be one of: any, none, upnp, pmp, extip:<IP>"
        defaultValue: "any" .}: string

      case genesisType*: GenesisType
      of eth1:
        depositWeb3Url* {.
          desc: "URL of the Web3 server to observe Eth1",
          defaultValue: ""}: string

        depositContractAddress* {.
          desc: "Address of the deposit contract",
          defaultValue: ""}: string

      of snapshot:
        validators* {.
          required
          desc: "Path to a validator private key, as generated by validator_keygen"
          longform: "validator"
          shortform: "v".}: seq[ValidatorKeyPath]

        stateSnapshot* {.
          desc: "Json file specifying a recent state snapshot"
          shortform: "s".}: Option[TypedInputFile[BeaconState, Json, "json"]]

      of quickStart:
        genesisTime* {.
          desc: "A unix timestamp marking the genesis start".}: uint64

        quickStartTotalValidators* {.
          longform: "totalValidators"
          desc: "Total number of validators in the network".}: uint64

        firstValidatorIndex* {.
          desc: "Index of the first attached validator".}: uint64

        attachedValidatorsCount* {.
          desc: "Number of validators to attach to this node".}: uint64

    of createTestnet:
      networkId* {.
        desc: "An unique numeric identifier for the network".}: uint8

      validatorsDir* {.
        desc: "Directory containing validator descriptors named vXXXXXXX.deposit.json"
        shortform: "d".}: InputDir

      totalValidators* {.
        desc: "The number of validators in the newly created chain".}: uint64

      firstValidator* {.
        desc: "Index of first validator to add to validator list"
        defaultValue: 0 .}: uint64

      lastUserValidator* {.
        desc: "The last validator index that will free for taking from a testnet participant"
        defaultValue: config.totalValidators - 1 .}: uint64

      bootstrapAddress* {.
        desc: "The public IP address that will be advertised as a bootstrap node for the testnet"
        defaultValue: "127.0.0.1".}: string

      bootstrapPort* {.
        desc: "The TCP/UDP port that will be used by the bootstrap node"
        defaultValue: defaultPort(config) .}: int

      genesisOffset* {.
        desc: "Seconds from now to add to genesis time"
        shortForm: "g"
        defaultValue: 5 .}: int

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot".}: OutFile

      outputNetwork* {.
        desc: "Output file where to write the initial state snapshot".}: OutFile

    of importValidator:
      keyFiles* {.
        longform: "keyfile"
        desc: "File with validator key to be imported (in hex form)".}: seq[ValidatorKeyPath]

    of updateTestnet:
      discard

proc defaultPort*(config: BeaconNodeConf): int =
  if config.network == "testnet1": 9100
  else: 9000

proc defaultDataDir*(conf: BeaconNodeConf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  let networkDir = if conf.network in ["testnet0", "testnet1", "mainnet"]:
    conf.network
  else:
    # TODO: This seems silly. Perhaps we should error out here and ask
    # the user to specify dataDir as well.
    "tempnet"

  getHomeDir() / dataDir / "BeaconNode" / networkDir

proc validatorFileBaseName*(validatorIdx: int): string =
  # there can apparently be tops 4M validators so we use 7 digits..
  fmt"v{validatorIdx:07}"

