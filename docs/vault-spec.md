# Kaspa post-quantum vault — specification

A vault is a pay-to-script-hash address whose redeem script verifies a
**hash-based post-quantum signature** over a digest reconstructed from the
spending transaction. Two signature schemes are defined:

| `scheme'` | scheme | standard | stateful |
|---|---|---|---|
| `1` | LMS `SHA256_M32_H15` / LMOTS `SHA256_N32_W2` | RFC 8554, NIST SP 800-208 | yes |
| `2` | SLH-DSA-SHA2-128s | FIPS 205 | no |

> **Status: experimental, unaudited, testnet only.** This document describes
> what is implemented and measured, not a standard. Everything here is
> address-affecting: a change to any constant, layout or algorithm below moves
> every address derived under it, and coins at the old address become
> unspendable. See [§9 Reproducibility](#9-reproducibility).

Companion documents: `README.md` (rationale and quickstart), `DEVNOTES.md`
(engineering record, not published).

---

## 1. What the design requires from consensus

Nothing new. The verifier is emitted from opcodes that already exist:

- **KIP-10** — transaction introspection, 8-byte arithmetic
- **KIP-17** — further introspection
- **v1 transactions** — the `compute_budget` field and granular script pricing

All shipped in the **Toccata** upgrade, which is live on mainnet. Verified
against a synced node (`rusty-kaspa` 2.0.1, virtual DAA ~523.5M, version-1
transactions in the tip block) rather than assumed from a source checkout:

```sh
cargo run -p vault-node --release --example node_probe -- ws://127.0.0.1:17110 mainnet
```

Toccata also raised the script limits, gated on a flag named
`covenants_enabled`:

| limit | pre-Toccata | post-Toccata |
|---|--:|--:|
| `MAX_SCRIPTS_SIZE` | 10,000 | 1,000,000 |
| `MAX_SCRIPT_ELEMENT_SIZE` | 520 | 1,000,000 |
| `MAX_OPS_PER_SCRIPT` | 201 | 1,000,000 |
| `MAX_STACK_SIZE` | 244 | **244 (unchanged)** |

The limits were raised for covenants; large hash-based signatures becoming
verifiable is a side effect. The stack limit did **not** move, and that is the
binding constraint on the SLH-DSA witness — see [§6.3](#63-witness-encoding).

---

## 2. Key derivation

```
m / 101110' / 111111' / scheme' / account' / key_index'
     purpose   coin      1 = LMS
                         2 = SLH-DSA
```

| constant | value | note |
|---|---|---|
| `PURPOSE` | `101110` | binary for 46, after Kaspa's `44'`/`45'`, without occupying `46'` |
| `COIN_TYPE` | `111111` | SLIP-0044, Kaspa |
| `XI_DOMAIN` | `"KaspaPQV-v1"` | shared by every scheme; see below |

**Every level is hardened**, and this is load-bearing rather than cautious.
Kaspa's standard path is non-hardened below the account and its addresses
publish public keys, so an adversary who recovers an on-chain key by Shor could
use BIP32's parent-xpub weakness to climb to the account key and derive
everything beneath it — including hardened children. A distinct hardened
purpose severs that path. Recovering non-hardened derivation in the
post-quantum setting is an open research problem, so hardened-only is the only
sound option currently available.

**Never export an xpub for any ancestor of the vault branch.**

### 2.1 The scheme seed

```
xi = SHA-256( XI_DOMAIN || ser256(k_child) )        # 32 bytes
```

The child private key is hashed rather than used directly: a BIP32 key is an
integer mod the secp256k1 order and so is not uniform over 32 bytes, and the
domain separator removes any ambiguity about *which* 32 bytes are meant.

`XI_DOMAIN` separates *constructions*, not schemes: `scheme'` is already inside
the path, so two schemes derived from one mnemonic reach this point with
different child keys. One tag is therefore correct for all of them.

It read `KaspaPQV-LMS-v1` while LMS was the only scheme. That was never a
functional problem, but it made the primary scheme's derivation look like a
copy-paste error in a design whose central argument is that address-affecting
constants must be named carefully. Corrected before any mainnet funds existed,
which was the last cheap moment to do it.

### 2.2 LMS key material

`xi` is the deterministic keygen seed for `LmsSigningKey::new_internal`,
`LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W2`: 32,768 one-time keys, public key
`(I, T[1])`.

### 2.3 SLH-DSA key material

FIPS 205 defines `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`, but the
reference implementation keeps it private and exposes only a
draws-from-an-RNG form. The three secrets are therefore derived and supplied
through a seeded RNG:

```
KEY_DOMAIN = "KaspaPQV-SLH-DSA-SHA2-128s-v1"

SK.seed = SHA-256( KEY_DOMAIN || "sk.seed" || xi )[0..16]
SK.prf  = SHA-256( KEY_DOMAIN || "sk.prf"  || xi )[0..16]
PK.seed = SHA-256( KEY_DOMAIN || "pk.seed" || xi )[0..16]
```

Three independent hashes rather than one 48-byte stream, so a change to how one
field is derived cannot shift the others.

**This makes the address depend on an implementation detail**: that keygen
draws `SK.seed`, then `SK.prf`, then `PK.seed`, 16 bytes each, and nothing
else. Three things guard it:

1. `fips205` is pinned to **`=0.4.1`** exactly.
2. The seeded RNG has a fixed **48-byte budget and errors past it**, so a
   version that draws a different *amount* fails loudly rather than producing an
   unrecoverable vault.
3. Keygen asserts the budget was fully consumed and that `PK.seed` came back
   verbatim in the public key, which pins the *order* as well as the total.

Signing is deterministic (`hedged = false`, so `opt_rand = PK.seed`) and draws
no randomness at all; the signer passes an RNG that refuses every request rather
than linking an OS RNG into a cold-storage path.

---

## 3. The binding digest

Kaspa has no sighash opcode and the introspection range provides no equivalent,
so the message a vault signs is **reconstructed inside the redeem script** from
introspection, and independently off-chain when the transaction is built.

**These two constructions must agree byte for byte.** They do not fail loudly
when they diverge: the signature verifies against a message nobody will ever
reconstruct and the UTXO becomes unspendable with no error anywhere.

### 3.1 Canonical preimage

All integers little-endian at fixed width, matching `OpNum2Bin`:

```
offset  size  field
     0     2  tx_version        u16 LE
     2    32  outpoint_txid
    34     4  outpoint_index    u32 LE
    38     1  output_count      u8
then per output i:
         8  amount            u64 LE
         2  spk_len           u16 LE      = len(script) + 2
   spk_len  spk                           = spk_version BE || script
```

```
D = SHA-256(preimage)
```

**The SPK endianness trap.** `spk` is the wire encoding `OpTxOutputSpk` pushes,
which is `spk_version.to_be_bytes() || script` — the SPK version is
**big**-endian while every other integer here is little-endian.
`OpTxOutputSpkLen` measures that same encoding, so `spk_len == len(script) + 2`.
Version 0 is endian-symmetric and standardness rejects anything higher, so a
byte-order mistake is invisible in every realistic test. The frozen vectors
include a non-zero SPK version for this reason.

**Field widths are halved by sign-magnitude.** `OpNum2Bin` emits little-endian
*sign-magnitude*, so the top bit of the last byte is the sign:

| field | maximum |
|---|--:|
| `tx_version` | `0x7FFF` |
| `outpoint_index` | `2^31 - 1` |
| `output_count` | `127` |
| `spk_len` | `32767` |
| `amount` | `i64::MAX` |

The serializer refuses out-of-range values rather than encoding something the
script cannot reproduce.

### 3.2 Frozen test vector

Canonical spend: version 1, txid `00 01 02 … 1f`, outpoint index 0, two P2SH
outputs of 100,000,000 and 899,000,000 sompi with 35-byte scripts of `0xaa` and
`0xbb`.

```
preimage  0100 000102...1f 00000000 02
          00e1f50500000000 2500 0000 aa*35
          c0a6953500000000 2500 0000 bb*35

D         a9c47f7c925c11286be8e565d24834447af4368bd4db40014b5f749285be056f
```

Edge vector (non-zero SPK version, non-zero outpoint index, asymmetric script
lengths):

```
D         621b10ab9ee4621a122399f00f08a6ea647b0a4a94976fe1c931555ce3a23815
```

Pinned in `crates/vault-core/tests/frozen_binding_digest.rs`. Differential
tests prove the in-script and off-chain constructions agree with *each other*;
these prove they agree with what was signed before.

### 3.3 What it does and does not cover

Covered: transaction version, this input's outpoint, and every output's amount
and script public key.

**Not covered:** `compute_commit`. The declared compute budget is therefore
adjustable after signing, which is what lets a spend be measured and then
rebuilt with the budget it actually needs.

Also not covered: other inputs. Both redeem scripts assume **exactly one vault
input**. See [§10](#10-open-questions).

---

## 4. Address format

```
redeem_script  = emit(scheme, public_key, output_count, …)
script_hash    = BLAKE2b-256(redeem_script)
spk            = OpBlake2b <32> script_hash OpEqual        # standard P2SH
address        = bech32(prefix, ScriptHash, script_hash)
```

A vault address is an ordinary P2SH address. Kaspa has three address versions
(`PubKey`, `PubKeyECDSA`, `ScriptHash`) and a vault is the third, so **no wallet
can label it as post-quantum**; the marker lives only in the holder's records.

The script hash is BLAKE2b-**256**, so the address commits to 256 bits and
carries no quantum weakness of its own (Grover gives ~2^128).

The signature script is a standard P2SH reveal:

```
signature_script = <witness pushes> <redeem_script>
```

There is no cap on signature-script length in mempool policy; the binding
constraint is transaction mass.

---

## 5. Canonical spend shape

Kaspa script has no loops, so output iteration is unrolled and a vault commits
to **exactly two outputs**: destination and change.

```
CANONICAL_OUTPUT_COUNT = 2
```

A different count is a different script and therefore a different address. It
is a property of the vault, not a spend-time choice. A single-output sweep
would be a second address type.

Under SLH-DSA, change returns to the **same address**. Under LMS it must go to
leaf `q+1`, because leaf `q` is burned by the spend.

---

## 6. SLH-DSA-SHA2-128s (`scheme' = 2`)

### 6.1 Parameters

FIPS 205 Table 2, security category 1.

| | |
|---|--:|
| `n` | 16 |
| `h` / `d` / `h'` | 63 / 7 / 9 |
| `a` / `k` | 12 / 14 |
| `lg_w` / `w` | 4 / 16 |
| `len1` / `len2` / `len` | 32 / 3 / 35 |
| `m` | 30 |
| public key | 32 bytes |
| signature | 7,856 bytes (491 × 16) |

`128s`, not `128f`: `f` has 22 hypertree layers against 7, so ~11,600 hashes
instead of ~3,900. Fast signing and slow verification is the wrong trade when
verification is the on-chain cost.

### 6.2 Compressed ADRS

Every hash is `Trunc_16( SHA-256( PK.seed || toByte(0,48) || ADRS^c || M ) )`.
The first 64 bytes are one constant SHA-256 block. `ADRS^c` is 22 bytes:

```
offset  size  field
     0     1  layer address        (low byte of a 4-byte word)
     1     8  tree address         (low 8 bytes of a 12-byte word)
     9     1  type                 (low byte of a 4-byte word)
    10     4  word 1   key pair address | key pair | tree height (=0)
    14     4  word 2   chain address    | 0        | tree height
    18     4  word 3   hash address     | 0        | tree index
```

**All three words are big-endian**, the opposite of every integer in the binding
digest. `OpNum2Bin` produces little-endian sign-magnitude, so each runtime index
requires an explicit byte reversal in script.

`setTypeAndClear` zeroes all three words. Tree height aliases **word 2**, not
word 1; writing it where the key pair address lives is silent.

Types: `WOTS_HASH 0`, `WOTS_PK 1`, `TREE 2`, `FORS_TREE 3`, `FORS_ROOTS 4`.

### 6.3 Witness encoding

A signature is 491 `n`-byte elements and `MAX_STACK_SIZE` is **244, counting
both stacks**. Elements cannot be pushed individually.

The signature is pushed as **123 blobs of 4 elements** (`BLOB_ELEMS = 4`), in
signature order. The verifier's prologue moves them to the alt stack — which
reverses them into a queue — and slices each blob when reached, pushing its
elements back above the remaining blobs so they pop in order.

Cost model, verified against the engine: `OpSubstr` is charged only for the
substring it produces and inter-stack moves are free, but `OpSubstr` *consumes*
the blob, so each extraction needs an `OpDup` of the remainder. Extracting `e`
elements from one blob costs `16·e·(e+1)`; across `E` elements in blobs of `e`
that is `16·E·(e+1)` — **linear in blob size, not quadratic in the signature**.

`BLOB_ELEMS` is part of the redeem script and therefore part of the address.
Measured sweep:

| elems | blobs | redeem B | script units | peak stack |
|--:|--:|--:|--:|--:|
| 2 | 246 | 87,965 | — | 263 ✗ |
| 3 | 164 | 88,783 | 1,205,194 | 182 |
| **4** | **123** | **89,193** | **1,214,346** | **142** |
| 8 | 62 | 89,864 | 1,247,530 | 85 |
| 100 | 5 | 91,731 | 1,959,242 | 120 |
| 491 | 1 | 91,863 | — | 506 ✗ |

Both ends fail against the 244-item limit.

### 6.4 Verifier structure

```
prologue    move witness blobs to the alt stack
binding     reconstruct D from introspection            (§3)
H_msg       two SHA-256 calls -> a 30-byte digest
indices     md, idx_tree, idx_leaf carved from digest
FORS        14 trees x (1 leaf hash + 12-node path), then T_k
hypertree    7 layers x (35 Winternitz chains + 9-node path)
epilogue    compare against the pinned PK.root
```

`H_msg` for the SHA2 parameter sets is an inner SHA-256 followed by one
MGF1-SHA-256 block; `m` is 30 and MGF1 emits 32 per block, so the counter is
always zero and the loop unrolls to nothing.

The signed message is `M' = toByte(0,1) || toByte(|ctx|,1) || ctx || D`. The
vault uses an **empty context**, so the prefix is two zero bytes. Omitting them
produces a self-consistent scheme that no standards-conforming implementation
can verify.

Winternitz chain length depends on a message digit, so all 15 steps are emitted
and gated on `digit <= step`. Untaken `OpIf` branches cost script *bytes* and
zero script *units*, so a spend pays worst-case size for average-case compute.

Merkle sibling order depends on an index bit, so both orders are emitted; the
branch is a single `OpSwap`, since `H(pfx || a || b)` and `H(pfx || b || a)`
differ only in operand order.

---

## 7. LMS (`scheme' = 1`)

`LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W2`: `h = 15` (32,768 one-time keys),
`w = 2`, `p = 133` chains, `n = 32`.

The leaf index `q` is a **script constant**, so each leaf has its own redeem
script and its own address. Hash prefixes stay literal pushes (zero runtime
cost), one-time-key state becomes discoverable from the UTXO set, and the
Merkle path's odd/even branching resolves at generation time.

Witness, pushed bottom first:

```
path[h-1] … path[0], y[p-1] … y[0], C
```

The signed message is absent — the script rebuilds it.

**Sign-once is a wallet obligation.** Kaspa cannot enforce it without a
consensus change. See [§8.1](#81-statefulness-and-off-chain-signing).

Parameters chosen by measurement: `w = 1` cannot run at all (265 chain values
exceed the 244-item stack limit) and `w = 4` costs 39% more mass; `h = 20`
would cost 4.5% more mass but pushes keygen to 178 s.

---

## 8. Security considerations

### 8.1 Statefulness and off-chain signing

An LM-OTS private key is `p` values; a signature is a partial opening of it.
Two signatures under one key expose `min(a_i, b_i)` per chain, and published
recovery is roughly **2^34 hashes from two signatures**.

Pinning `q` into the script means key `q` can only spend the UTXO at address
`q`, so on-chain state is discoverable. **This does not cover signatures the
chain never sees.** Proof-of-reserves, sign-a-message-for-a-service and similar
flows produce signatures no scan can observe, and nothing in LMS distinguishes a
transaction digest from any other message. Signing an attestation with leaf `q`
and later spending from leaf `q` is two signatures under one one-time key.

The blast radius is bounded — compromise takes that leaf's balance, not the
vault — but it is a bound, not a fix.

**SLH-DSA has no such constraint.** Every WOTS+ key inside the hypertree signs a
*fixed* subtree root determined at keygen, and the leaf index comes from
`H_msg` over 2^63 positions rather than a counter. One-time keys are still used
exactly once; the construction arranges that reuse cannot arise. If a vault must
sign anything that is not a transaction, use `scheme' = 2`.

### 8.2 Output value floors

Two independent limits, and neither subsumes the other:

- **Absolute.** Storage mass (KIP-9) scales with the inverse of an output's
  value, so below roughly 0.019 KAS the mass exceeds the standard limit whatever
  else the transaction looks like. `DUST_THRESHOLD` is **0.02 KAS**, checked by
  value so the rejection names the cause.
- **Relative.** Change small *compared to the UTXO consumed* is also too
  expensive. No fixed threshold — measured at ~0.29% of a 10 KAS input.

Clearing the absolute floor is not sufficient: change of exactly 0.02 KAS
against a 10 KAS LMS input still overshoots the block storage limit. Both are
checked before signing.

### 8.3 Compute budget

Script units are data-dependent — a Winternitz chain runs from its message
digit to its maximum — and vary ~8.5% between signatures. **A budget derived
from a different signature under-declares, and consensus rejects that
outright.** It must come from the signature being broadcast. Script *bytes* do
not vary, so addresses and fee estimates are stable.

The budget is not covered by the binding digest ([§3.3](#33-what-it-does-and-does-not-cover)),
so a spend is measured under an unconstrained budget and rebuilt declaring what
it needs, without re-signing.

### 8.4 Ordering

Everything that can cause a rejection is evaluated on the **unsigned**
transaction, using Kaspa's own mass calculator: fee floor, compute mass,
transient mass, storage mass, output standardness, spend shape.

For LMS this is critical — a rejected transaction cannot be repaired, because
changing the fee changes the digest and the one-time key cannot sign again, so
the coins strand at that leaf. For SLH-DSA the stakes are lower: a rejected
transaction is rebuilt and re-signed.

### 8.5 Security level

SLH-DSA-128s is NIST category 1. FIPS 205 approves it; SP 800-208 has no
category 1 parameter set for *stateful* hash-based signatures, which is why
stateful designs land at category 3. Whether a decade-scale vault should use
`192s` instead is [open](#10-open-questions).

---

## 9. Reproducibility

A vault address is the hash of a script this workspace **compiles**. An
independent build that differs by one byte derives a different address from the
same mnemonic, and anyone funding it loses the coins with no error anywhere.

- `Cargo.lock` is committed; `fips205` and `oxicrypt-lms` are pinned exactly.
- `rust-toolchain.toml` pins the compiler.
- Frozen vectors pin mnemonic → xi → public key → script hash → address for both
  schemes, and the binding digest independently.
- `kaspa-vault artifacts` prints every address-affecting value, derived from the
  published BIP39 test mnemonic. It takes no key material and touches no
  network.

Any difference in that output is a compatibility break.

---

## 10. Open questions

**Multi-input.** Both redeem scripts assume exactly one vault input, so UTXOs
cannot be consolidated: five received payments are five separate 97 KB spends.
Fixing this means a different unrolled script and probably a distinct address
type.

**Security level.** `128s` (category 1) versus `192s` for a decade-scale vault,
against roughly double the on-chain cost.

**KIP registration.** `PURPOSE = 101110'` and the `scheme'` assignments are
chosen, not registered. `Derivation` carries the purpose as a field so two
branches can be scanned during a migration if a KIP ever assigns one.

**Never run on mainnet.** Toccata is live there and the opcodes, transaction
format and mass rules are identical, so no consensus obstacle remains — but
"should work" and "has worked" are different claims.

**Not audited.** No independent review of either generator, the wallets, or the
derivation.

---

## 11. Measured costs

Testnet-10, confirmed spends.

| | SLH-DSA-SHA2-128s | LMS h=15 w=2 |
|---|--:|--:|
| redeem script | 89,235 B | 19,717 B |
| transaction | 97,472 B | 24,890 B |
| script units | 1,330,069 | 373,146 |
| compute budget | 136 | 40 |
| normalized mass | 194,944 | 49,780 |
| fee | 0.2339 TKAS | 0.0597 TKAS |
| spends per block | 2 | ~10 |
| key generation | 0.18 s | 5.96 s |

Transient mass dominates both: a vault spend is large but cheap to verify, so
the honest optimisation target is script **bytes**, not script units.

```
SLH-DSA  4f4f96c2494d741b3cc0f30bde3a15faa956bbdfeed60ba184cbef185dc2cd6c
SLH-DSA  25a8dc25735ec649f3d99379f969c5c7761d8546514c783050b34c5ad6c8d3d4   spends the above's change
LMS      9df246be429549dfd7635f2c95c6fed580f491632db9ee5777a9fab22fce755a
LMS      7dd3834583a9b501f969420b4aff1b7ef6fe51b8151463ba30672fa2671e0a00
```
