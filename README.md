# kaspa-vault

Post-quantum vault addresses for Kaspa. A vault is an ordinary P2SH address
whose spend condition is a **hash-based signature verified directly in Kaspa
script** — no zero-knowledge proof, no precompile, and no opcode added for it.

Four schemes are implemented and **all four have spent on testnet-10**.

| | **SLH-DSA-128s** | **SLH-DSA-128-24** | **SLH-DSA-128-24d2** | **LMS h=15 w=2** |
|---|---|---|---|---|
| standard | FIPS 205 | SP 800-230 ipd | **none** | RFC 8554 / SP 800-208 |
| stateful | **no** | **no** | **no** | yes — each leaf signs once |
| signatures per key | 2^64 | 2^24 | 2^24 | 2^15 |
| addresses per vault | **1** | **1** | **1** | 32,768 |
| safe to sign off-chain | **yes** | **yes** | **yes** | no |
| signature | 7,856 B | **3,856 B** | 6,176 B | 4,780 B |
| redeem script | 89,235 B | **21,752 B** | 33,664 B | 19,717 B |
| key generation | 0.08 s | ~100 s | 0.09 s | 5.96 s |
| signing | 0.52 s | 23 s | **0.20 s** | 0.02 s |

Measured transaction sizes and fees are in [Measured costs](#measured-costs).
The short version: **`SLH-DSA-SHA2-128-24` spends for 1.04x LMS's transaction
bytes and fewer script units than LMS.** Statelessness used to cost 3.9x on this
chain. At these parameters it costs about 4%.

None is strictly better. The three SLH-DSA sets delete an entire category of
operational failure; LMS is cheap and demands that you never sign the same key
twice, including for things the chain never sees. Among the SLH-DSA sets, the
axis is what a 2^24 signature limit buys: roughly a quarter of the on-chain
bytes, at a signing cost that depends entirely on `d`.

**A 2^24 limit is not a limit for a vault.** A vault spending once a day reaches
it in about 45,000 years. FIPS 205 sizes every standard set for 2^64 signatures
under one key; NIST's SP 800-230 draft (April 2026) proposes selling that unused
headroom back as signature size, for exactly the "sign-once, verify-many" case a
vault is. On a chain that charges for bytes, that is the trade worth having.

**`128-24d2` is not a standard.** It appears in no NIST document. It is carried
here because `128-24`'s `d = 1` puts a single XMSS tree of 4,194,304 leaves in
front of every signature — about 100 seconds to generate a key and 23 to sign,
on six cores — and `d = 2` buys that back almost entirely for 2,320 more
signature bytes. Whether that is a good trade is what measuring it is for. It has none of
the other two sets' security analysis behind it and should never be described as
standardised.

The normative description — derivation, the binding digest byte layout, the
compressed ADRS, witness encoding, security considerations and the frozen
vectors — is in **[`docs/vault-spec.md`](docs/vault-spec.md)**. This README is
the rationale and the quickstart.

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
cargo run -p vault-node --release --example node_probe -- ws://127.0.0.1:17110 mainnet
```

The more interesting way to state this: Toccata was designed for covenants and
introspection, not for post-quantum anything, and it turns out to be sufficient
for a FIPS 205 verifier.

Pre-Toccata limits made this impossible outright — 201 operations, 10 KB
scripts and 520-byte stack elements, against the ~10,000 operations and 19 KB
script an LMS spend needs, let alone SLH-DSA's 22 to 89 KB.

**What has *not* been done is running it on mainnet.** That is a testing gap,
not a consensus one: the opcodes, the transaction format and the mass rules are
identical on both networks, and the same code paths would execute. See
[Limitations](#limitations).

## Confirmed on-chain

Testnet-10:

```
SLH-DSA-128s      4f4f96c2494d741b3cc0f30bde3a15faa956bbdfeed60ba184cbef185dc2cd6c   first spend
SLH-DSA-128s      25a8dc25735ec649f3d99379f969c5c7761d8546514c783050b34c5ad6c8d3d4   spends its own change
SLH-DSA-128s      3197116e1b8008111b94fddc8595d35d0a79676dbbfb3696dc231427d6a60c54   funds a 128-24d2 vault
SLH-DSA-128-24    7d74a4308bf2a7379fb3602ec947722eb890ba83f8e63347381aa7f7c7e89e45   first spend
SLH-DSA-128-24    586e6e019603a3eead40b924da31359146129af924c553e0f738ef86263cfe08   spends its own change
SLH-DSA-128-24d2  1f890510e29a44d22cf5d29b60920c4fea7ce292a4eb752cf5dbc0d93c089df0   first spend
SLH-DSA-128-24d2  0aaaf1768c15515bfe20bad6a2324eeda4aac83bf0e4f94378a8e137f25af826   spends its own change
SLH-DSA-128-24d2  18878fec837b47fec47140eb841f82c2d52b1451df41cc9a546ef0042f78dabe   and its change again
LMS               9df246be429549dfd7635f2c95c6fed580f491632db9ee5777a9fab22fce755a   leaf 0 -> 1
LMS               7dd3834583a9b501f969420b4aff1b7ef6fe51b8151463ba30672fa2671e0a00   leaf 1 -> 2
```

`128-24d2` spent three times under an earlier `k = 11` FORS choice as well —
`4a83c79e…`, `bf6c80e7…`, `da02dcc1…` — which a security review replaced. Those
describe a set this build no longer emits and are noted only so the history is
not silently dropped.

**The second transaction of each stateless pair is the one that matters.** It
spends the first one's change with the same key, from the same address, over a
different message — the operation that exposes an LMS one-time key. Nothing was
consulted or recorded between the two, and the address did not move. The LMS
rows walk `leaf 0 -> 1 -> 2` instead, burning a one-time key per spend and
leaving dead addresses behind. That contrast is the whole argument.

**The measured cost matched the lab.** The size, mass and compute budget a node
accepted are the numbers the test suite reported against a fabricated UTXO —
for `128-24`, to within one transaction byte and two units of normalized mass
([Measured costs](#measured-costs)). Nothing needed revising once real coins
were involved.

**`SLH-DSA-SHA2-128-24` costs less to verify than LMS.** Measured side by side
in one process — same spend shape, same engine, same mass parameters — it is
25,926 bytes against LMS's 24,891, but **266,270 script units against 373,146**,
at a 0.0519 TKAS fee floor against 0.0498. A stateless post-quantum signature
for about 4% more than a stateful one, now confirmed on-chain rather than
argued.

## Why hash-based, and why these

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
directly in Kaspa script.** Which of its parameter sets is a separate question,
and one this workspace answers by measuring three of them rather than picking.

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

**The price of that is measured, not estimated.** Against LMS it was 3.9x the
on-chain bytes when `128s` was the only stateless option. The 2^24 parameter
sets cut that: `128-24d2` is 1.4x, and `128-24` less still. Statelessness is no
longer expensive on this chain — it is roughly the same price as the stateful
scheme, and the reason is that a vault never needed 2^64 signatures.

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

`--set` picks the parameter set; it defaults to `128s`, and each set is a
different address under the same mnemonic:

```sh
kaspa-vault slh-address --set 128s        # FIPS 205            (default)
kaspa-vault slh-address --set 128-24d2    # 2^24 limit, d=2     (not a standard)
kaspa-vault slh-address --set 128-24      # 2^24 limit, d=1     (minutes to derive)
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

### One mnemonic, every scheme

```
m / 101110' / 111111' / scheme' / account' / key_index'   ->  xi (32 bytes)
     purpose   coin      1' = LMS
                         2' = SLH-DSA-SHA2-128s
                         3' = SLH-DSA-SHA2-128-24
                         4' = SLH-DSA-SHA2-128-24d2
```

`xi = SHA-256("KaspaPQV-v1" || ser256(k_child))`, hashed rather than used raw
because a BIP32 key is not uniform over 32 bytes and the domain separator
removes any ambiguity about which bytes are meant. One tag serves every scheme:
it separates *constructions*, not schemes — the `scheme'` level already gives
each scheme an independent branch.

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
H_msg -> m-byte digest -> (md, idx_tree, idx_leaf)
FORS        k trees x (1 leaf hash + a-node path)
hypertree   d layers x (len Winternitz chains + h'-node path)

           FORS            hypertree              signature
128s       14 x (1 + 12)   7 x (35 chains + 9)    7,856 B
128-24      6 x (1 + 24)   1 x (68 chains + 22)   3,856 B
128-24d2   15 x (1 + 14)   2 x (68 chains + 12)   6,176 B
```

The hypertree position is derived from the message, so nothing has to be
remembered between signatures. Change returns to the **same address**, which a
stateful vault cannot do because its current leaf is burned by the spend.

One emitter serves all three sets; they differ only in constants. That is not
tidiness for its own sake — it is what makes the two unstandardised sets
believable, since the `128s` instantiation is held against `fips205`
key-for-key and signature-for-signature by a test.

Two things make this fit inside consensus limits:

- **Unrolled and gated.** A Winternitz chain's length depends on a message
  digit, so all `w - 1` steps are emitted and gated on `digit <= step` — 15
  under `128s`, 3 under the `w = 4` sets. Untaken `OpIf` branches cost script
  *bytes* and zero script *units*, so a spend pays worst-case size for
  average-case compute. Dropping `w` from 16 to 4 is most of why the 2^24 sets
  are so much smaller on-chain: it cuts the emitted chain steps from 3,675 to
  204 or 408, and pays for it in signature bytes the limit already bought back.
- **Blob-and-slice witness encoding.** A signature is 241 to 491 16-byte
  elements and `MAX_STACK_SIZE` is 244, counting both stacks — so even
  `128-24`'s 241 elements do not fit once the verifier's working frame is on
  the stack with them. The signature is pushed as blobs of four and sliced back
  apart. Slicing is linear in blob size, not quadratic in the signature, and
  measures at ~3% of total script units.

**Where a set costs you is the signer.** `128-24`'s `d = 1` means one XMSS tree
of `2^22` leaves, and every signature builds all of it: about 1.5 billion hashes
against `128s`'s 4 million. That is deliberate in the draft — signing is a build
server, verification is everyone — but for a vault whose signer may be an
air-gapped laptop it is the half you notice.

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

All four schemes, one process, the same spend shape (one input, two standard
outputs), the same `TxScriptEngine`, the same `MassCalculator` with testnet
parameters. Every number is produced by Kaspa's own code
(`cargo test --release -p slh-script --test comparison -- --ignored --nocapture`):

| | stateful | signatures | redeem B | tx bytes | script units | norm mass | per block | fee |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| LMS h=15 w=2 | yes | 2^15 | 19,717 | 24,891 | 375,226 | 49,782 | 10 | 0.0498 |
| SLH-DSA-128s | no | 2^64 | 89,235 | 97,473 | 1,285,456 | 194,946 | 2 | 0.1949 |
| **SLH-DSA-128-24** | no | 2^24 | **21,752** | **25,926** | **266,270** | 51,852 | 9 | **0.0519** |
| SLH-DSA-128-24d2 | no | 2^24 | 33,664 | 40,194 | 455,267 | 80,388 | 6 | 0.0804 |

**The result worth stating plainly: `SLH-DSA-SHA2-128-24` costs 1.04x LMS's
transaction bytes and is *cheaper to verify* than LMS.** A stateless
post-quantum vault at a stateful vault's price. The statefulness problem that
this design spent a rewrite managing costs, at these parameters, about 4%.

**The harness predicted the chain to within a byte, for both new sets:**

| | `128-24` harness | chain | `128-24d2` harness | chain |
|---|--:|--:|--:|--:|
| transaction | 25,926 B | 25,925 B | 40,194 B | 40,193 B |
| normalized mass | 51,852 | 51,850 | 80,388 | 80,386 |
| fee floor | 0.0519 | 0.0519 | 0.0804 | 0.0804 |
| script units | 266,270 | 267,546 / 267,553 | 455,267 | 454,056 – 473,019 |
| compute budget | 29 | 29 | 48 | **48 / 50 / 48** |

Each set's unit counts are consecutive spends of one key, each spending the
previous one's change. They differ because a Winternitz chain runs from its
message digit — which is why the budget has to come from the signature actually
being broadcast, not from the parameter set.

**`128-24d2` is the one where that actually bit.** Its three spends spanned
18,963 units, 4.2%, and the declared budget moved 48 → 50 → 48. Earlier rounds
made the narrower band look like a property of `w = 4`: `128s` moved 136 → 142
across three spends, while `128-24` held 29 and `128-24d2` at `k = 11` held 43.
Those were two-sample observations. With 136 chains of up to 3 steps the
standard deviation is a few thousand units either way, so a tight pair was luck
rather than structure, and the wider spread here is the same distribution seen
three times instead of twice.

The `128s` and LMS rows have their own confirmed figures — 97,472 B at 0.2339
TKAS and 24,890 B at 0.0597 TKAS — differing from the harness by
data-dependence and a different fee choice, not a different construction.

**The on-chain saving is larger than the signature saving**, which was the
surprise. Halving the signature halves the witness, but the redeem script falls
4.1x — because the script is mostly emitted Winternitz chain steps,
`d·len·(w-1)`, which is 3,675 for `128s` and 204 for `128-24`. Dropping `lg(w)`
from 4 to 2 is what does it; it costs signature bytes in `len`, and the 2^24
limit is what already paid for those. The two changes are not independent
improvements — the second finances the first.

**Transient mass dominates every row.** A vault spend is large but cheap to
verify, so you pay for bytes rather than computation — which is why the honest
optimisation target is script *bytes*, not script units.

**Where `128-24` costs you is the signer**: about 100 s to generate a key and
23 s to sign, against 0.08 s and 0.52 s for `128s`. A confirmed spend took
2m05s wall clock end to end. That is `d = 1` — one XMSS tree of 4,194,304
leaves, rebuilt for every signature. `128-24d2` is the same signature limit with
`d = 2`, which buys that back for 14,268 more transaction bytes.

Timings are wall clock from the CLI on a six-core i5-9600K **without SHA-NI**;
a CPU with the SHA extensions would be several times faster, and the current
leaf builder only reaches about 3.7 of 6 cores, so this is an upper bound
rather than a floor.

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
or the derivation. The SLH-DSA redeem script is 22 to 89 KB of unrolled opcodes
depending on the parameter set; a bug fails in both directions — too permissive
and anyone spends the vault, too strict and it is bricked.

**Never run on mainnet.** Everything here has been exercised on testnet-10
only. Toccata is live on mainnet and the required opcodes, transaction format
and mass rules are identical there, so no consensus obstacle remains — but
"should work" and "has worked" are different claims and only the second one is
worth trusting with real value.

**The address depends on a compiled artifact.** The redeem script is emitted by
this workspace, so a changed generator is a changed address — and nothing in a
funded address announces which construction produced it. That is pinned rather
than left open: `Cargo.lock` is committed, `oxicrypt-lms` is exact-pinned and
`fips205` — now only the oracle a test compares against, not something an
address passes through — is pinned too, `rust-toolchain.toml` fixes the
compiler, frozen vectors carry
mnemonic through to bech32 address for every scheme, and `kaspa-vault artifacts`
lets a third party check their tree against yours. What is *not* claimed is a
bit-reproducible build in the strict sense — binaries have not been compared
across machines. The property that matters for an address is that the emitted
script is deterministic, and that is what is pinned and checkable.

**Parameters are baked into the address.** The derivation purpose, the canonical
two-output shape, LMS's `h` and `w`, and SLH-DSA's parameter set and witness
blob size all change the redeem script and therefore every address. They cannot
be altered after funding, and `kaspa-vault artifacts` is how you notice if one
has.

**Nothing in an address says which parameter set it belongs to.** Every SLH-DSA
public key here is 32 bytes, so a key cannot say either. A spend built for the
wrong set fails against the script, after the coins have already been sent.
Record the set alongside the address — `kaspa-vault slh-address --set …` prints
both.

**Both 2^24 sets have spent on testnet-10**, each spending its own change —
`128-24` twice, `128-24d2` three times. What neither has had is review: see the
two paragraphs above this one.

**`SLH-DSA-SHA2-128-24` is a draft parameter set and `SLH-DSA-SHA2-128-24d2` is
not a parameter set at all.** SP 800-230 is an initial public draft and its
numbers can change before it is final; if they do, `128-24` here becomes a set
NIST does not define, and addresses funded under it stay spendable only by this
code. `128-24d2` was never anyone's proposal. Neither carries the standing
`128s` has, and only `128s` should hold anything that matters.

**What `128-24d2` does have is arithmetic, not review.** Its FORS forgery bound
has been computed twice, independently, each derivation first validated against
SP 800-230's own published figure for `128-24`. Those bounds put it at or above
**SP 800-230's category-1 variant** — 179.64 bits against 128.63 at the same
2^24 design point, and a 128-bit crossing at 2^29.25 signatures against roughly
2^24.1 ([spec §8.5.1](docs/vault-spec.md#851-computed-bounds)). That is one term
of a security argument, not a proof, and nobody with authority over the standard
has looked at this set.

**LMS is stateful.** Losing the spend journal *and* signing again from the same
address exposes a one-time key. The pinned-leaf design makes state recoverable
from the chain, but a signature issued and never broadcast is invisible to a
scan — and an off-chain signature is invisible by construction. If you need to
sign anything that is not a transaction, use SLH-DSA.

**Vault addresses are indistinguishable on-chain.** Kaspa has three address
versions (`PubKey`, `PubKeyECDSA`, `ScriptHash`) and a vault is the third, so no
wallet can label it as post-quantum. The marker lives only in your records. The
script hash is BLAKE2b-256, so the address itself carries no quantum weakness.

**Unexercised paths**: mainnet; multi-input spends (every script assumes exactly
one vault input); for LMS, the roll from leaf 32,767 to the next key index.

**Key material is not zeroized.** Fine for a CLI that exits in seconds, not fine
for a daemon or GUI.

**Scope.** This protects coins at rest against Shor. It does not address quantum
mining, does not migrate the existing UTXO set, and is not a general payment
format.

## Layout

```
crates/vault-core/    binding digest, script writer, derivation, preflight
                      — everything every scheme must agree on
crates/slh-script/    three parameter sets, ADRS, reference verifier and
                      signer, script generator
crates/slh-wallet/    deterministic keygen, vault, spending
crates/lms-script/    RFC 8554 parameters and generator
crates/lms-wallet/    vault, spend journal, assembly
crates/vault-node/      wRPC client (Public Node Network or your own node)
crates/vault-cli/       the kaspa-vault binary
crates/vault-harness/   differential tests against the real consensus engine
docs/vault-spec.md    the normative specification
```

`slh-wallet` has no journal, no leaf cursor, no gap limit and no migration path.
That is the deliverable, not an omission.

Tests execute generated scripts with Kaspa's own `TxScriptEngine` — the same
type a node runs — so a script that passes does so for the reasons it would
on-chain. Both generators are differentially tested against independent
reference implementations (`fips205` for SLH-DSA, `oxicrypt-lms` for LMS),
including their *rejections*, with negative controls on every positive
assertion.

SP 800-230's sets have no third-party implementation to test against — nobody
ships the draft yet — so `slh-script` carries its own FIPS 205 signer, and what
stands behind the two new sets is that it is *the same code*: one parameterised
implementation whose `128s` instantiation reproduces `fips205` key-for-key and
signature-for-signature (`reference_oracle::the_signer_reproduces_fips205`).

```sh
cargo test --release --workspace
```

Everything involving `SLH-DSA-SHA2-128-24` is `#[ignore]`d, because holding one
of its keys costs about 100 seconds of hashing. Those tests are the only ones in the
suite that are, and they run with:

```sh
cargo test --release --workspace -- --ignored
```

## Verifying your build

A vault address is the hash of a script this workspace *compiles*, so an
independent build that differs by one byte derives a different address from the
same mnemonic. `Cargo.lock` is committed, `oxicrypt-lms` and `fips205` are
pinned exactly, and `rust-toolchain.toml` pins the compiler. Since the SLH-DSA
signer moved in-tree, no SLH-DSA address depends on a third-party crate at all
— but the check that matters is still:

```sh
kaspa-vault artifacts
```

It derives every address-affecting value from the published BIP39 test
mnemonic, takes no key material and touches no network. `SLH-DSA-SHA2-128-24` is
the one thing it skips — reproducing it means 2^22 WOTS+ public keys, and a
verification aid nobody waits two minutes for is a verification aid nobody
runs; `kaspa-vault slh-address --set 128-24` reproduces it on demand. Compare
against [`docs/vault-spec.md`](docs/vault-spec.md) §3.2 and §9. **Any difference is a
compatibility break — do not fund an address from a build that prints something
else.**

## Licence

Apache-2.0 OR MIT.
