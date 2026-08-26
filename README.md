# kaspa-vault

Post-quantum vault addresses for Kaspa. A vault is an ordinary P2SH address
whose spend condition is an **LMS hash-based signature** (RFC 8554 / NIST
SP 800-208) verified directly in Kaspa script.

No consensus change, no new opcodes, no deployment transaction. A vault address
is derived offline from a mnemonic you already have, and is receivable today
from any wallet that can send to P2SH.

> **Status: working on testnet-10, not audited, not for mainnet funds.**
> Two spends have been verified by real Kaspa consensus. See
> [Limitations](#limitations) before trusting it with anything.

## Why hash-based

Kaspa's default address type is bare pay-to-pubkey, so essentially the entire
UTXO set exposes Schnorr public keys in the clear. Anyone wanting protection
against Shor's algorithm today has no option that does not involve trusting a
future migration to arrive in time.

LMS needs nothing from the chain but SHA-256, which Kaspa already has as
`OpSHA256`. Its security rests on hash preimage resistance alone — no lattices,
no elliptic curves, no new assumptions, and no dependency on a zero-knowledge
verifier whose version might drift over the decade a vault sits untouched.

The cost is that LMS is **stateful**: each one-time key signs exactly once. The
design below turns that from a footgun into a property the chain enforces.

## Prerequisites

This workspace depends on `rusty-kaspa` **by path**, so it can execute generated
scripts with the same `TxScriptEngine` a node runs rather than a
reimplementation. That is deliberate — the test suite's value comes from using
consensus code directly — but it means you need the node source checked out as a
sibling directory:

```
your-workspace/
├── rusty-kaspa/     <- github.com/kaspanet/rusty-kaspa (Toccata, v2.0.1+)
└── kaspa-vault/     <- this repository
```

and the paths in the root `Cargo.toml` adjusted to match if your layout differs
(they currently point at `../L1-logic/rusty-kaspa`).

Toccata must be active on the network you target. It supplies the script limits
this design needs — pre-Toccata caps were 201 ops, 10,000-byte scripts and
520-byte elements, against the ~10,000 ops, ~19 KB script and 4,780-byte
signature a vault spend requires.

## Quickstart

```sh
cargo build --release
cp .env.example .env && chmod 600 .env     # add your mnemonic
./target/release/kaspa-vault info
```

Derive addresses, check balances, spend:

```sh
kaspa-vault addresses --count 4
kaspa-vault balance   --count 4
kaspa-vault spend --to kaspatest:qr... --amount 1000000000        # preview only
kaspa-vault spend --to kaspatest:qr... --amount 1000000000 --yes  # sign + broadcast
```

`spend` **previews by default**. Without `--yes` it prints the plan and exits
without signing. Credentials come from `.env`, the environment, or `--mnemonic`
/ `--key`; a flag always wins over the file.

Deriving a vault takes a few seconds — it builds 32,768 one-time public keys to
compute the Merkle root. That is not a hang.

## How it works

### One key, 32,768 addresses

```
m / 101110' / 111111' / scheme' / account' / key_index'   ->  xi (32 bytes)
     purpose   coin      1'=LMS                                |
                                                               +-- LMS key, h=15
                                                                    |
                                                                    +-- leaf 0    -> address
                                                                    +-- leaf 1    -> address
                                                                    +-- ...
                                                                    +-- leaf 32767
```

`xi = SHA-256("KaspaPQV-LMS-v1" || ser256(k_child))`, hashed rather than used
raw because a BIP32 key is not uniform over 32 bytes and the domain separator
removes any ambiguity about which bytes are meant.

**Every level is hardened**, and that is load-bearing rather than cautious.
Kaspa's standard path is non-hardened below the account, and its addresses
publish public keys. A quantum adversary could Shor an on-chain key, use BIP32's
parent-xpub weakness to climb to the account key, and derive anything beneath
it. A separate hardened purpose severs that path. (Recovering non-hardened
derivation in the post-quantum setting is an open research problem, so this is
the only sound option available.)

### The leaf index is pinned into the script

Each leaf gets its **own redeem script**, with `q` baked in as a constant, and
therefore its own address. Three things follow:

- Hash prefixes stay literal pushes, which cost zero script units at runtime.
- **One-time-key state lives in the UTXO set.** Leaf `q` can only ever spend the
  UTXO at address `q`, so "which key have I burned" is answered by looking at
  which address holds coins — no counter file to survive a decade and a
  mnemonic restore.
- The Merkle path's odd/even branching resolves at generation time, so the
  emitted script contains no conditionals for it.

Spending sends change to leaf `q+1`, so the vault walks forward on its own.

### The redeem script

```
reconstruct D from introspection      (tx version, outpoint, every output amount + SPK)
verify LMS signature over D           (133 Winternitz chains, 15 Merkle levels, unrolled)
```

The signed message is **absent from the witness** — the script rebuilds it from
the transaction being verified. That is what stops anyone holding a valid
signature from redirecting the funds.

Kaspa script has no loops, so output iteration is unrolled and a vault commits
to one canonical spend shape: destination plus change.

### Sign-once, enforced structurally

Signing two different messages under one LM-OTS key exposes it. QRL, which has
run the same construction in production since 2018, publishes recovery at
roughly **2^34 hashes from two signatures** — hours on a consumer GPU. This is
not a degradation to manage; it is a loss of funds.

Kaspa cannot help: QRL rejects index reuse at consensus, and adding such a rule
here would need the consensus change this design exists to avoid. So the wallet
enforces it:

- A leaf that has never signed may sign once. **The record is durable before the
  signature is returned**, so a crash cannot leave an issued signature untracked.
- Asked to sign the *same* digest again, it returns the stored signature.
  Rebroadcasting is idempotent and safe.
- Asked to sign a *different* digest, it refuses.

That last case is the fee bump, and the answer is never to re-sign. Which is why
**every check that could get a transaction rejected runs before signing** — fee
floor, compute mass, transient mass, storage mass, output standardness — using
Kaspa's own mass calculator rather than a reimplementation.

## Measured costs

From a confirmed testnet-10 spend, `LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W2`:

| | |
|---|--:|
| transaction size | 24,890 bytes |
| normalized mass | 49,780 |
| script units | 373,146 |
| compute budget declared | 40 units |
| fee | 0.0597 TKAS |
| spends per block | ~10 |
| one-time keys per vault | 32,768 |
| key generation | ~5.6 s |

Transient mass dominates: a vault spend is large but cheap to verify, so you pay
for bytes rather than computation.

Parameters were chosen by measurement. `w=1` cannot run at all — its 265 chain
values exceed Kaspa's 244-item stack limit. `w=4` costs 39% more mass because
its unrolled script is larger. `h=15` gives 32,768 keys for 3% more mass than
32; `h=20` would cost only 4.5% more but pushes key generation to 178 seconds.

## Limitations

**Not audited.** No independent review of the script generator, the wallet, or
the derivation. The generated redeem script is ~19 KB of unrolled opcodes; a bug
in it fails in both directions — too permissive and anyone spends the vault, too
strict and it is bricked.

**Stateful.** Losing the spend journal *and* signing again from the same address
exposes a one-time key. The pinned-leaf design makes state recoverable from the
chain, but a signature issued and never broadcast is invisible to a scan.

**Parameters are baked into the address.** `h`, `w`, the derivation purpose, and
the canonical two-output shape all change the redeem script and therefore every
address. They cannot be altered after funding.

**Vault addresses are indistinguishable on-chain.** Kaspa has three address
versions (`PubKey`, `PubKeyECDSA`, `ScriptHash`) and a vault is the third, so no
wallet can label it as post-quantum. The marker lives only in your records.

**Unexercised paths**: the roll from leaf 32,767 to the next key index,
multi-input spends (the script assumes exactly one vault input), and mainnet.

**Scope.** This protects coins at rest against Shor. It does not address quantum
mining, does not migrate the existing UTXO set, and is not a general payment
format.

## Layout

```
crates/lms-script/    RFC 8554 parameters, binding digest, script generation
crates/lms-wallet/    derivation, vault, spend journal, preflight, assembly
crates/lms-node/      wRPC client (Public Node Network or your own node)
crates/lms-cli/       the kaspa-vault binary
crates/lms-harness/   differential tests against the real consensus engine
```

Tests execute generated scripts with Kaspa's own `TxScriptEngine` — the same
type a node runs — so a script that passes does so for the reasons it would
on-chain.

```sh
cargo test --release --workspace
```

## Licence

Apache-2.0 OR MIT.
