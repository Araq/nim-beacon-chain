import
  os, ospaths,
  nimcrypto/utils, stew/endians2, stint,
  ./conf, ./extras, ./ssz,
  spec/[crypto, datatypes, digest, helpers]

func get_eth1data_stub*(deposit_count: uint64, current_epoch: Epoch): Eth1Data =
  # https://github.com/ethereum/eth2.0-pm/blob/e596c70a19e22c7def4fd3519e20ae4022349390/interop/mocked_eth1data/README.md
  let
    epochs_per_period = SLOTS_PER_ETH1_VOTING_PERIOD div SLOTS_PER_EPOCH
    voting_period = current_epoch.uint64 div epochs_per_period.uint64

  Eth1Data(
    deposit_root: hash_tree_root(voting_period),
    deposit_count: deposit_count,
    block_hash: hash_tree_root(hash_tree_root(voting_period).data),
  )

const sigs = [
  "8684b7f46d25cdd6f937acdaa54bdd2fb34c78d687dca93884ba79e60ebb0df964faa4c49f3469fb882a50c7726985ff0b20c9584cc1ded7c90467422674a05177b2019661f78a5c5c56f67d586f04fd37f555b4876a910bedff830c2bece0aa",
  "a2c86c4f654a2a229a287aabc8c63f224d9fb8e1d77d4a13276a87a80c8b75aa7c55826febe4bae6c826aeeccaa82f370517db4f0d5eed5fbc06a3846088871696b3c32ff3fdebdb52355d1eede85bcd71aaa2c00d6cf088a647332edc21e4f3",
  "a5a463d036e9ccb19757b2ddb1e6564a00463aed1ef51bf69264a14b6bfcff93eb6f63664e0df0b5c9e6760c560cb58d135265cecbf360a23641af627bcb17cf6c0541768d3f3b61e27f7c44f21b02cd09b52443405b12fb541f5762cd615d6e",
  "8731c258353c8aa46a8e38509eecfdc32018429239d9acad9b634a4d010ca51395828c0c056808c6e6df373fef7e9a570b3d648ec455d90f497e12fc3011148eded7265b0f995de72e5982db1dbb6eca8275fc99cdd10704b8cf19ec0bb9c350",
  "90b20f054f6a2823d66e159050915335e7a4f64bf7ac449ef83bb1d1ba9a6b2385da977b5ba295ea2d019ee3a8140607079d671352ab233b3bf6be45c61dce5b443f23716d64382e34d7676ae64eedd01babeeb8bfd26386371f6bc01f1d4539",
  "99df72b850141c67fc956a5ba91abb5a091538d963aa6c082e1ea30b7f7e5a54ec0ff79c749342d4635e4901e8dfc9b90604d5466ff2a7b028c53d4dac01ffb3ac0555abd3f52d35aa1ece7e8e9cce273416b3cf582a5f2190e87a3b15641f0c",
  "a4023f36f4f354f69b615b3651596d4b479f005b04f80ef878aaeb342e94ad6f9acddf237309a79247d560b05f4f7139048b5eee0f08da3a11f3ee148ca76e3e1351a733250515a61e12027468cff2de193ab8ee5cd90bdd1c50e529edda512b",
  "81c52ada6d975a5b968509ab16fa58d617dd36a6c333e6ed86a7977030e4c5d37a488596c6776c2cdf4831ea7337ad7902020092f60e547714449253a947277681ff80b7bf641ca782214fc9ec9b58c66ab43c0a554c133073c96ad35edff101",
  "b4aab8f6624f61f4f5eb6d75839919a3ef6b4e1b19cae6ef063d6281b60ff1d5efe02bcbfc4b9eb1038c42e0a3325d8a0fcf7b64ff3cd9df5c629b864dfdc5b763283254ccd6cfa28cff53e477fb1743440a18d76a776ec4d66c5f50d695ca85",
  "9603f7dcab6822edb92eb588f1e15fcc685ceb8bcc7257adb0e4a5995820b8ef77215650792120aff871f30a52475ea31212aa741a3f0e6b2dbcb3a63181571306a411c772a7fd08826ddeab98d1c47b5ead82f8e063b9d7f1f217808ee4fb50",
  "92b04a4128e84b827b46fd91611acc46f97826d13fbdcbf000b6b3585edd8629e38d4c13f7f3fde5a1170f4f3f55bef21883498602396c875275cb2c795d4488383b1e931fefe813296beea823c228af9e0d97e65742d380a0bbd6f370a89b23",
  "89ac6297195e768b5e88cbbb047d8b81c77550c9462df5750f4b899fc0de985fa9e16fccc6c6bd71124eb7806064b7110d534fb8f6ccaf118074cd4f4fac8a22442e8facc2cd380ddc4ebf6b9c2f7e956f418279dc04a6737ede6d7763396ed9",
  "8adee09a19ca26d5753b9aa447b0af188a769f061d11bf40b32937ad3fa142ca9bc164323631a4bb78f0a5d4fd1262010134adc723ab377a2e6e362d3e2130a46b0a2088517aee519a424147f043cc5007a13f2d2d5311c18ee2f694ca3f19fc",
  "90dc90a295644da5c6d441cd0b33e34b8f1f77230755fd78b9ecbd86fd6e845e554c0579ab88c76ca14b56d9f0749f310cd884c193ec69623ccd724469268574c985ee614e80f00331c24f78a3638576d304c67c2aa6ce8949652257581c18a5",
  "9338c8b0050cdb464efae738d6d89ac48d5839ce750e3f1f20acd52a0b61e5c033fa186d3ed0ddf5856af6c4815971b00a68002b1eba45f5af27f91cad04831e32157fecf5fb091a8087829e2d3dd3438e0b86ff8d036be4a3876fa0dfa60e6c",
  "8819f719f7af378f27fe65c699b5206f1f7bbfd62200cab09e7ffe3d8fce0346eaa84b274d66d700cd1a0c0c7b46f62100afb2601270292ddf6a2bddff0248bb8ed6085d10c8c9e691a24b15d74bc7a9fcf931d953300d133f8c0e772704b9ba"
]

when ValidatorPrivKey is BlsValue:
  func makeInteropPrivKey*(i: int): ValidatorPrivKey =
    discard
    {.fatal: "todo/unused?".}
else:
  func makeInteropPrivKey*(i: int): ValidatorPrivKey =
    var bytes: array[32, byte]
    bytes[0..7] = uint64(i).toBytesLE()

    let
      # BLS381-12 curve order - same as milagro but formatted different
      curveOrder =
        "52435875175126190479447740508185965837690552500527637822603658699938581184513".parse(UInt256)

      privkeyBytes = eth2hash(bytes)
      key = (UInt256.fromBytesLE(privkeyBytes.data) mod curveOrder).toBytesBE()

    ValidatorPrivKey.init(key)

const eth1BlockHash* = block:
  var x: Eth2Digest
  for v in x.data.mitems: v = 0x42
  x

func makeWithdrawalCredentials*(k: ValidatorPubKey): Eth2Digest =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_deposit-contract.md#withdrawal-credentials
  var bytes = eth2hash(k.getBytes())
  bytes.data[0] = BLS_WITHDRAWAL_PREFIX.uint8
  bytes

var i = 0
proc makeDeposit*(
    pubkey: ValidatorPubKey, privkey: ValidatorPrivKey, epoch = 0.Epoch,
    amount: Gwei = MAX_EFFECTIVE_BALANCE.Gwei,
    flags: UpdateFlags = {}): Deposit =
  var
    ret = Deposit(
      data: DepositData(
        amount: amount,
        pubkey: pubkey,
        withdrawal_credentials: makeWithdrawalCredentials(pubkey)))

  when false:
    if skipValidation notin flags:
      ret.data.signature =
        bls_sign(
          privkey, signing_root(ret.data).data, compute_domain(DOMAIN_DEPOSIT))
  else:
    ret.data.signature.initFromBytes fromHex(sigs[i])

  when defined(serialization_tracing):
    debugEcho "privkey ", privkey
    debugEcho "signing root ", signing_root(ret.data)
    debugEcho "domain ", compute_domain(DOMAIN_DEPOSIT)
    debugEcho "deposit signature ", ret.data.signature

  inc i

  ret
