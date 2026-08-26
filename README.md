# kaspa-vault

Post-quantum vault addresses for Kaspa. A vault is an ordinary P2SH address
whose spend condition is a **hash-based signature verified directly in Kaspa
script** — no zero-knowledge proof, no precompile, and no opcode added for it.

Two schemes are implemented and both have spent on testnet-10:

| | **SLH-DSA-SHA2-128s** | **LMS h=15 w=2** |
|---|---|---|
| standard | FIPS 205 | RFC 8554 / NIST SP 800-208 |
| stateful | **no** | yes — each leaf signs once |
| addresses per vault | **1** | 32,768 |
| safe to sign off-chain | **yes** | no |
| transaction size | 97,472 B | **24,890 B** |
| fee (measured) | 0.2339 TKAS | **0.0597 TKAS** |
| spends per block | 2 | **~10** |
| key generation | **0.18 s** | 5.96 s |

Neither is strictly better. SLH-DSA costs about 3.9x the bytes and deletes an
entire category of operational failure; LMS is cheap and demands that you never
sign the same key twice, including for things the chain never sees.

> **Status: working on testnet-10. Not audited. Not for mainnet funds.**
> Four spends have been verified by real Kaspa consensus — see
> [Confirmed on-chain](#confirmed-on-chain). Read [Limitations](#limitations)
> before trusting either scheme with anything.

## What this depends on, precisely

The verifier is built entirely from opcodes that already exist. **Nothing was
added to Kaspa for post-quantum support, and none is needed.** It uses:

- **KIP-10** — transaction introspection opcodes and 8-byte arithmetic
- **KIP-17** — further introspection
- **v1 transactions** — the `compute_budget` field and granular script pricing

All of these arrived with the **Toccata** upgrade, which is **live on mainnet**.
Verified against a synced mainnet node rather than assumed: `rusty-kaspa`
v2.0.1, virtual DAA score ~523.5M, and version-1 transactions present in the
current tip block — v1 being exactly the format that carries `compute_budget`.
Reproduce it with:

```sh
cargo run -p lms-node --release --example node_probe -- ws://127.0.0.1:17110 mainnet
```

The more interesting way to state this: Toccata was designed for covenants and
introspection, not for post-quantum anything, and it turns out to be sufficient
for a FIPS 205 verifier.

Pre-Toccata limits made this impossible outright — 201 operations, 10 KB
scripts and 520-byte stack elements, against the ~10,000 operations and 19 KB
script an LMS spend needs, let alone SLH-DSA's 89 KB.

**What has *not* been done is running it on mainnet.** That is a testing gap,
not a consensus one: the opcodes, the transaction format and the mass rules are
identical on both networks, and the same code paths would execute. See
[Limitations](#limitations).

## Confirmed on-chain

Testnet-10:

```
SLH-DSA  4f4f96c2494d741b3cc0f30bde3a15faa956bbdfeed60ba184cbef185dc2cd6c   first spend
SLH-DSA  25a8dc25735ec649f3d99379f969c5c7761d8546514c783050b34c5ad6c8d3d4   spends its own change
LMS      9df246be429549dfd7635f2c95c6fed580f491632db9ee5777a9fab22fce755a   leaf 0 -> 1
LMS      7dd3834583a9b501f969420b4aff1b7ef6fe51b8151463ba30672fa2671e0a00   leaf 1 -> 2
```

The second SLH-DSA transaction is the one that matters. It spends the first
one's change **with the same key, from the same address, over a different
message** — the operation that exposes an LMS one-time key. Nothing was
consulted or recorded between the two, and the address did not move.

The measured cost matched the lab exactly: the size, mass and compute budget a
node accepted are the numbers the test suite reported against a fabricated UTXO.
Nothing needed revising once real coins were involved.

## Why hash-based, and why these two

Kaspa's default address type is bare pay-to-pubkey, so essentially the entire
UTXO set exposes Schnorr public keys in the clear. Anyone wanting protection
against Shor's algorithm today has no option that does not involve trusting a
future migration to arrive in time.

Hash-based signatures need nothing from the chain but a hash function Kaspa
already has. Security rests on preimage resistance alone — no lattices, no
elliptic curves, no new assumptions, and no dependency on a verifier whose
version might drift over the decade a vault sits untouched.

**Why not a lattice scheme.** Kaspa script has `OpSHA256`, `OpBlake2b` and
`OpBlake3`, and no Keccak or SHAKE. ML-DSA (FIPS 204) opens verification by
rejection-sampling a polynomial matrix from ~13 KB of SHAKE128 output, and
Falcon needs the same primitive for hash-to-point. Implementing Keccak-f[1600]
in script — 24 rounds of 5x5 64-bit lanes, with `OpLShift`/`OpRShift` disabled —
is not a real option. That reframes a zkVM as a *compatibility shim* for SHAKE
rather than a scaling technique.

**SLH-DSA is therefore the only stateless post-quantum signature verifiable
directly in Kaspa script.**

## The statefulness problem, and what it cost to fix

LMS is efficient because each one-time key signs exactly once, and this design
originally argued that the chain enforces that: the leaf index is pinned into
the redeem script, so key `q` can only ever spend the UTXO at address `q`, and
"which key have I burned" is answered by scanning addresses.

That argument has a hole, raised by a Kaspa core developer: **it does not
account for off-chain signing.** Proof-of-reserves, sign-a-message-for-a-service
and similar flows produce signatures the chain never sees. Nothing in LMS
distinguishes a transaction digest from any other message — both are bytes to
`ots_sign`. Sign an attestation with leaf `q`, later spend from leaf `q`, and
that is two signatures under one one-time key. QRL publishes recovery at roughly
**2^34 hashes from two signatures**.

The critique is correct and it applies. The partial mitigation is real but not
an answer: because `q` is pinned, compromise takes that leaf's balance, not the
vault.

SLH-DSA dissolves the problem rather than managing it. Every WOTS+ key inside
its hypertree signs a *fixed* subtree root determined at key generation, and the
leaf index comes from the message —
`(md, idx_tree, idx_leaf) = H_msg(R, PK.seed, PK.root, M)` over 2^63 positions —
rather than from a counter. An attestation derives its own position, a
transaction derives another, and they never interact.

**The price of that is measured, not estimated: 3.9x the on-chain bytes.**

## Prerequisites

This workspace depends on `rusty-kaspa` **by path**, so it executes generated
scripts with the same `TxScriptEngine` a node runs rather than a
reimplementation. That is deliberate — the test suite's value comes from using
consensus code directly — but it means you need the node source as a sibling:

```
your-workspace/
├── rusty-kaspa/     <- github.com/kaspanet/rusty-kaspa (Toccata, v2.0.1+)
└── kaspa-vault/     <- this repository
```

Adjust the paths in the root `Cargo.toml` if your layout differs (they currently
point at `../L1-logic/rusty-kaspa`).

## Quickstart

```sh
cargo build --release
cp .env.example .env && chmod 600 .env     # add your mnemonic
./target/release/kaspa-vault info
```

**SLH-DSA (stateless):**

```sh
kaspa-vault slh-address
kaspa-vault slh-balance
kaspa-vault slh-spend --to kaspatest:qr... --amount 2200000000 --dry-run
kaspa-vault slh-spend --to kaspatest:qr... --amount 2200000000
```

**LMS (stateful):**

```sh
kaspa-vault addresses --count 4
kaspa-vault balance   --count 4
kaspa-vault spend --to kaspatest:qr... --amount 1000000000        # preview only
kaspa-vault spend --to kaspatest:qr... --amount 1000000000 --yes  # sign + broadcast
```

`--amount` is in sompi; 1 KAS is 100,000,000. Both spend commands refuse to
broadcast without confirmation — `slh-spend` prompts, `spend` previews unless
given `--yes`.

Credentials come from `.env`, the environment, or `--mnemonic` / `--key`; a flag
always wins over the file. `KASPA_VAULT_MNEMONIC_SLH` and `KASPA_VAULT_KEY_SLH`
point the stateless scheme at a *different* seed, falling back to the shared
pair when unset. Every address prints which variable it came from.

## How it works

### One mnemonic, both schemes

```
m / 101110' / 111111' / scheme' / account' / key_index'   ->  xi (32 bytes)
     purpose   coin      1' = LMS
                         2' = SLH-DSA
```

`xi = SHA-256("KaspaPQV-LMS-v1" || ser256(k_child))`, hashed rather than used
raw because a BIP32 key is not uniform over 32 bytes and the domain separator
removes any ambiguity about which bytes are meant. The tag names LMS for
historical reasons and is deliberately unchanged for SLH-DSA: it separates
*constructions*, not schemes — the `scheme'` level already gives each scheme an
independent branch, and renaming the tag would move every funded LMS address.

**Every level is hardened**, and that is load-bearing rather than cautious.
Kaspa's standard path is non-hardened below the account, and its addresses
publish public keys. A quantum adversary could Shor an on-chain key, use BIP32's
parent-xpub weakness to climb to the account key, and derive anything beneath
it. A separate hardened purpose severs that path. (Recovering non-hardened
derivation in the post-quantum setting is an open research problem, so this is
the only sound option available.)

**Never export an xpub for any ancestor of the vault branch.**

### What the signature commits to

Both schemes sign the same thing: a **binding digest** the redeem script
reconstructs from transaction introspection.

```
version, outpoint txid, outpoint index, output count,
then per output: amount, spk length, spk
```

The signed message is **absent from the witness**. That is what stops anyone
holding a valid signature from redirecting the funds. Kaspa script has no loops,
so output iteration is unrolled and a vault commits to one canonical spend
shape: destination plus change.

There is exactly one implementation of this, in `vault-core`, shared by both
schemes. It is the component where two copies silently diverging would brick
UTXOs with no error anywhere, so there are not two copies.

### SLH-DSA: one address, reusable

```
H_msg -> 30-byte digest -> (md, idx_tree, idx_leaf)
FORS         14 trees x (1 leaf hash + 12-node path)
hypertree     7 layers x (35 Winternitz chains + 9-node path)
```

The hypertree position is derived from the message, so nothing has to be
remembered between signatures. Change returns to the **same address**, which a
stateful vault cannot do because its current leaf is burned by the spend.

Two things make this fit inside consensus limits:

- **Unrolled and gated.** A Winternitz chain's length depends on a message
  digit, so all 15 steps are emitted and gated on `digit <= step`. Untaken
  `OpIf` branches cost script *bytes* and zero script *units*, so a spend pays
  worst-case size for average-case compute.
- **Blob-and-slice witness encoding.** A signature is 491 16-byte elements and
  `MAX_STACK_SIZE` is 244, counting both stacks. The signature is pushed as 123
  blobs and sliced back apart. Slicing is linear in blob size, not quadratic in
  the signature, and measures at ~3% of total script units.

### LMS: 32,768 addresses, each spending once

Each leaf gets its own redeem script with `q` baked in as a constant, and
therefore its own address. Hash prefixes stay literal pushes (zero runtime
cost), one-time-key state becomes discoverable from the UTXO set, and the Merkle
path's odd/even branching resolves at generation time.

Spending sends change to leaf `q+1`, so the vault walks forward on its own.

The wallet enforces sign-once, because Kaspa cannot:

- A leaf that has never signed may sign once. **The record is durable before the
  signature is returned**, so a crash cannot leave an issued signature untracked.
- Asked to sign the *same* digest again, it returns the stored signature.
  Rebroadcasting is idempotent and safe.
- Asked to sign a *different* digest, it refuses.

That last case is the fee bump, and the answer is never to re-sign. Which is why
**every check that could get a transaction rejected runs before signing** — fee
floor, compute mass, transient mass, storage mass, output standardness — using
Kaspa's own mass calculator rather than a reimplementation.

For SLH-DSA the same checks run in the same order, but the stakes are lower: a
rejected transaction is simply rebuilt and re-signed.

## Measured costs

From confirmed testnet-10 spends:

| | SLH-DSA-SHA2-128s | LMS h=15 w=2 |
|---|--:|--:|
| redeem script | 89,235 B | 19,717 B |
| transaction size | 97,472 B | 24,890 B |
| script units | 1,330,069 | 373,146 |
| compute budget declared | 136 units | 40 units |
| normalized mass | 194,944 | 49,780 |
| fee | 0.2339 TKAS | 0.0597 TKAS |
| spends per block | 2 | ~10 |
| key generation | 0.18 s | 5.96 s |

**Transient mass dominates both.** A vault spend is large but cheap to verify,
so you pay for bytes rather than computation — which is why the honest
optimisation target is script *bytes*, not script units.

Parameters were chosen by measurement, not argument. For LMS, `w=1` cannot run
at all — its 265 chain values exceed the 244-item stack limit — and `w=4` costs
39% more mass. For SLH-DSA, `128f` was rejected because its 22 hypertree layers
mean roughly 11,600 hashes against `128s`'s 3,900: fast signing and slow
verification is the wrong trade when verification is the on-chain cost.

## Two constraints that will bite you

**Outputs have two separate minimum sizes, and neither subsumes the other.**
Storage mass (KIP-9) scales with the inverse of an output's value, producing an
*absolute* floor — below roughly 0.019 KAS nothing is viable regardless of the
input, so the wallet enforces 0.02 KAS by value — and a *relative* one, where
change that is small compared to the UTXO being consumed is also too expensive.
Change of exactly 0.02 KAS against a 10 KAS input still overshoots the block
storage limit. Both are checked before signing and named separately in the
rejection.

**The compute budget must come from the signature being broadcast.** Script
units are data-dependent — a Winternitz chain runs from its message digit to its
maximum — so they vary about 8.5% between signatures. A budget derived from a
*different* signature under-declares, and consensus rejects that outright.
Script *bytes* do not vary, so addresses and fee estimates are stable.

## Limitations

**Not audited.** No independent review of either script generator, the wallets,
or the derivation. The SLH-DSA redeem script is 89 KB of unrolled opcodes; a bug
fails in both directions — too permissive and anyone spends the vault, too
strict and it is bricked.

**Never run on mainnet.** Everything here has been exercised on testnet-10
only. Toccata is live on mainnet and the required opcodes, transaction format
and mass rules are identical there, so no consensus obstacle remains — but
"should work" and "has worked" are different claims and only the second one is
worth trusting with real value.

**Reproducible builds are not yet pinned.** The redeem script is compiled from
source, so a changed generator is a changed address. Frozen derivation vectors
pin mnemonic through to bech32 address for both schemes, which turns drift into
a failing test — but the build itself is not yet reproducible, and that is a
prerequisite before mainnet funds.

**Parameters are baked into the address.** The derivation purpose, the canonical
two-output shape, LMS's `h` and `w`, and SLH-DSA's witness blob size all change
the redeem script and therefore every address. They cannot be altered after
funding.

**LMS is stateful.** Losing the spend journal *and* signing again from the same
address exposes a one-time key. The pinned-leaf design makes state recoverable
from the chain, but a signature issued and never broadcast is invisible to a
scan — and an off-chain signature is invisible by construction. If you need to
sign anything that is not a transaction, use SLH-DSA.

**Vault addresses are indistinguishable on-chain.** Kaspa has three address
versions (`PubKey`, `PubKeyECDSA`, `ScriptHash`) and a vault is the third, so no
wallet can label it as post-quantum. The marker lives only in your records. The
script hash is BLAKE2b-256, so the address itself carries no quantum weakness.

**Unexercised paths**: mainnet; multi-input spends (both scripts assume exactly
one vault input); for LMS, the roll from leaf 32,767 to the next key index.

**Key material is not zeroized.** Fine for a CLI that exits in seconds, not fine
for a daemon or GUI.

**Scope.** This protects coins at rest against Shor. It does not address quantum
mining, does not migrate the existing UTXO set, and is not a general payment
format.

## Layout

```
crates/vault-core/    binding digest, script writer, derivation, preflight
                      — everything both schemes must agree on
crates/slh-script/    FIPS 205 parameters, ADRS, reference verifier, generator
crates/slh-wallet/    deterministic keygen, vault, spending
crates/lms-script/    RFC 8554 parameters and generator
crates/lms-wallet/    vault, spend journal, assembly
crates/lms-node/      wRPC client (Public Node Network or your own node)
crates/lms-cli/       the kaspa-vault binary
crates/lms-harness/   differential tests against the real consensus engine
```

`slh-wallet` has no journal, no leaf cursor, no gap limit and no migration path.
That is the deliverable, not an omission.

Tests execute generated scripts with Kaspa's own `TxScriptEngine` — the same
type a node runs — so a script that passes does so for the reasons it would
on-chain. Both generators are differentially tested against independent
reference implementations (`fips205` for SLH-DSA, `oxicrypt-lms` for LMS),
including their *rejections*, with negative controls on every positive
assertion.

```sh
cargo test --release --workspace
```

## Licence

Apache-2.0 OR MIT.
