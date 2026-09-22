# Kaspa post-quantum vault — specification

A vault is a pay-to-script-hash address whose redeem script verifies a
**hash-based post-quantum signature** over a digest reconstructed from the
spending transaction. Four schemes are defined:

| `scheme'` | scheme | standard | stateful | signatures per key |
|---|---|---|---|--:|
| `1` | LMS `SHA256_M32_H15` / LMOTS `SHA256_N32_W2` | RFC 8554, NIST SP 800-208 | yes | 2^15 |
| `2` | SLH-DSA-SHA2-128s | FIPS 205 | no | 2^64 |
| `3` | SLH-DSA-SHA2-128-24 | NIST SP 800-230 **ipd** | no | 2^24 |
| `4` | SLH-DSA-SHA2-128-24d2 | **none** | no | 2^24 |

Schemes `3` and `4` do not have the standing scheme `2` does. SP 800-230 is an
initial public draft; `128-24d2` is stated in this workspace and nowhere else.
Both are specified, implemented and measured here on the same footing so that
the comparison is real — see [§8.5](#85-security-level) before using either.

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
     purpose   coin      1 = LMS-SHA256
                         2 = SLH-DSA-SHA2-128s
                         3 = SLH-DSA-SHA2-128-24
                         4 = SLH-DSA-SHA2-128-24d2
```

Each parameter set gets its own `scheme'` level rather than sharing `2'`.
Sharing would mean one seed generating two key pairs under two different
parameter sets — key material reused across schemes, which is the thing this
level exists to prevent.

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

### 2.1 How this differs from an ordinary Kaspa address

An ordinary Kaspa address **is** a public key:

```
m/44'/111111'/0'/0/0            <- non-hardened below the account
  -> secp256k1 private key
     -> 32-byte x-only Schnorr public key
        -> bech32(PubKey, pubkey)               kaspa:qr...

script public key:  OpData32 <pubkey> OpCheckSig
```

A vault address is the hash of a **program**:

```
m/101110'/111111'/2'/0'/0'      <- every level hardened
  -> secp256k1 private key
     -> xi = SHA-256("KaspaPQV-v1" || ser256(k_child))
        -> SLH-DSA key pair
           -> emit 22-89 KB redeem script (public key baked in as constants;
                                            size set by the parameter set)
              -> BLAKE2b-256(script)
                 -> bech32(ScriptHash, hash)    kaspa:pz...

script public key:  OpBlake2b OpData32 <script_hash> OpEqual
```

Four consequences:

**What is published.** The ordinary form puts the key *in the address*. A vault
publishes only a 256-bit hash; the post-quantum public key is not revealed until
the first spend.

**What the address commits to.** The ordinary form commits to one key. A vault
commits to the key *and* the verifier code, the two-output spend shape
([§5](#5-canonical-spend-shape)), the witness blob size
([§6.3](#63-witness-encoding)), and for LMS the leaf index — all inside one
hash. That is why every one of those is frozen: change any and the address
moves.

**The extra hop.** BIP32 yields a secp256k1 scalar, which is not uniform over 32
bytes; hash-based keygen needs uniform input. `xi` re-hashes it under a domain
separator ([§2.2](#22-the-scheme-seed)).

**Hardening.** The ordinary path is non-hardened below the account, which is
what makes watch-only xpubs work. A vault is hardened at every level,
deliberately: a non-hardened branch plus one Shor-recovered on-chain key yields
the parent private key, and from there everything beneath it.

The result is that an ordinary address is Shor-able **from the address alone**,
before it is ever spent. A vault address is a BLAKE2b-256 hash — nothing there
to Shor — and what it eventually reveals is a hash-based key to which Shor does
not apply.

### 2.2 The scheme seed

```
xi = SHA-256( XI_DOMAIN || ser256(k_child) )        # 32 bytes
```

The child private key is hashed rather than used directly: a BIP32 key is an
integer mod the secp256k1 order and so is not uniform over 32 bytes, and the
domain separator removes any ambiguity about *which* 32 bytes are meant.

`XI_DOMAIN` separates *constructions*, not schemes: `scheme'` is already inside
the path, so any two schemes derived from one mnemonic reach this point with
different child keys. One tag is therefore correct for all of them, and is not
named after any.

### 2.3 LMS key material

`xi` is the deterministic keygen seed for `LmsSigningKey::new_internal`,
`LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W2`: 32,768 one-time keys, public key
`(I, T[1])`.

### 2.4 SLH-DSA key material

`slh_keygen_internal(SK.seed, SK.prf, PK.seed)` (FIPS 205 Algorithm 18) is
called directly, with the three secrets derived from `xi`:

```
KEY_DOMAIN = "KaspaPQV-" || <parameter set name> || "-v1"

SK.seed = SHA-256( KEY_DOMAIN || "sk.seed" || xi )[0..16]
SK.prf  = SHA-256( KEY_DOMAIN || "sk.prf"  || xi )[0..16]
PK.seed = SHA-256( KEY_DOMAIN || "pk.seed" || xi )[0..16]
```

Three independent hashes rather than one 48-byte stream, so a change to how one
field is derived cannot shift the others. `KEY_DOMAIN` names the parameter set,
so one `xi` cannot produce two sets' key material — redundant with the `scheme'`
level, deliberately.

The three tags in use are `KaspaPQV-SLH-DSA-SHA2-128s-v1`,
`KaspaPQV-SLH-DSA-SHA2-128-24-v1` and `KaspaPQV-SLH-DSA-SHA2-128-24d2-v1`.

**The address depends on the seeds and the parameter set, and on nothing else.**
That was not always true. `fips205` keeps `slh_keygen_internal` private and
exposes only a draws-from-an-RNG form, so this wallet used to derive its key by
feeding that function an RNG returning exactly the bytes above — which made
every vault address depend on the order and size of three random draws inside a
third-party crate. `slh-script`'s own signer replaced it. `fips205` remains as
the oracle the `128s` instantiation is held against key-for-key and
signature-for-signature, which is a better job for it: a disagreement now fails
a test instead of moving a funded address.

The frozen derivation vectors confirm the change moved nothing: the `128s`
address, public key and redeem script are byte-identical across the switch.

Signing is deterministic (`opt_rand = PK.seed`, the unhedged variant) and draws
no randomness at all, so a cold signer needs no entropy source and a rebuilt
spend reproduces byte for byte.

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

Nor does anything in the address say which **parameter set** it belongs to, and
the public key cannot say either — all three SLH-DSA sets have a 32-byte public
key. The set reaches the address only through `emit`, so two sets over one key
are two addresses, and a spend built for the wrong one fails against the script
after the coins have been sent. The set belongs in the holder's records
alongside the address.

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

## 6. SLH-DSA (`scheme' = 2`, `3`, `4`)

### 6.1 Parameters

Three parameter sets, all SHA-2 at security category 1. One verifier emitter
serves all three; they differ only in the constants below.

| | `128s` | `128-24` | `128-24d2` |
|---|--:|--:|--:|
| `scheme'` | 2 | 3 | 4 |
| source | FIPS 205 Table 2 | SP 800-230 ipd Table 1 | **none** |
| signature limit | 2^64 | 2^24 | 2^24 |
| `n` | 16 | 16 | 16 |
| `h` / `d` / `h'` | 63 / 7 / 9 | 22 / 1 / 22 | 24 / 2 / 12 |
| `a` / `k` | 12 / 14 | 24 / 6 | 14 / 15 |
| `lg_w` / `w` | 4 / 16 | 2 / 4 | 2 / 4 |
| `len1` / `len2` / `len` | 32 / 3 / 35 | 64 / 4 / 68 | 64 / 4 / 68 |
| `m` | 30 | 21 | 31 |
| public key | 32 bytes | 32 bytes | 32 bytes |
| signature | 7,856 B (491 × 16) | 3,856 B (241 × 16) | 6,176 B (386 × 16) |

Every derived length is computed from FIPS 205 §11's formulas rather than
copied from a table, and checked against the two published tables
(`params::derived_lengths_match_the_published_tables`).

**`128-24d2` is not a standard.** It appears in no NIST document. It is
implemented, tested and measured here on exactly the same footing as the other
two so that the comparison is real, and it carries none of their security
analysis. Do not present it as standardised.

#### Why a 2^24 signature limit is not a constraint here

FIPS 205 sizes every standard set for 2^64 signatures under one key. A vault
spending once a day reaches 2^24 in roughly 45,000 years. SP 800-230 (initial
public draft, April 2026) proposes sets that buy that unused headroom back as
signature size, for exactly the "sign-once, verify-many" case a vault is.

#### Verification work

Worst-case `F`/`H` invocations follow from the parameters, so this part is
arithmetic rather than measurement:

```
FORS      k(1 + a) + 1
hypertree d[ len(w-1) + 1 + h' ]
H_msg     2                              (two SHA-256 calls)

128s      d=7,  h'=9,  a=12, k=14, w=16   183 + 3,745 + 2 = 3,930
128-24    d=1,  h'=22, a=24, k=6,  w=4    151 +   227 + 2 =   380
128-24d2  d=2,  h'=12, a=14, k=15, w=4    226 +   434 + 2 =   662
128f      d=22, h'=3,  a=6,  k=33, w=16   232 + 11,638 + 2 = 11,872
```

`w = 4` is what moves the hypertree column: a chain is at most three hashes
instead of fifteen, and paying for that in `len` (68 chains instead of 35) costs
signature bytes, which the 2^24 limit has already bought back. `128f` is listed
to be excluded — it trades hypertree depth for signing speed, which is the wrong
side of the trade when verification is the on-chain cost.

The measured figures are lower than these ceilings because chain steps are
gated: a spend executes roughly half the emitted steps
([§6.4](#64-verifier-structure)).

#### Signing work

The same parameters run the other way on the signer, and this is the axis
`128-24` loses on badly. One signature needs `2^h'` WOTS+ public keys per
hypertree layer, each `len` chains of `w - 1` hashes:

| | leaves per tree | hashes per signature | measured keygen | measured signing |
|---|--:|--:|--:|--:|
| `128s` | 512 | ~4 million | 0.08 s | 0.52 s |
| `128-24` | 4,194,304 | ~1.5 billion | **~100 s** | **23 s** |
| `128-24d2` | 4,096 | ~2 million | 0.09 s | 0.20 s |

Measured on six cores with the constant first hash block precomputed once per
key. `128-24`'s column is `d = 1` doing exactly what `d = 1` does, and it is the
reason `128-24d2` is carried alongside it: same signature limit, same `w`, two
orders of magnitude less signing, for 2,320 more signature bytes.

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

Types: `WOTS_HASH 0`, `WOTS_PK 1`, `TREE 2`, `FORS_TREE 3`, `FORS_ROOTS 4`. A
signer additionally uses `WOTS_PRF 5` and `FORS_PRF 6`, which no verifier ever
sees; they share this type field's namespace, so they are defined alongside
rather than separately.

The ADRS layout is the same for all three parameter sets, but two of its field
*widths* are not, because they are chosen to hold the largest index each set
addresses under `OpNum2Bin`'s sign-magnitude encoding:

| | FORS tree index | XMSS tree index |
|---|--:|--:|
| `128s` | 3 bytes (`k·2^a` = 57,344) | 2 bytes (`2^h'` = 512) |
| `128-24` | 4 bytes (100,663,296) | 3 bytes (4,194,304) |
| `128-24d2` | 3 bytes (245,760) | 2 bytes (4,096) |

The remaining bytes of each 4-byte word are literal zeros. A width one byte too
narrow produces a script that works for small indices and fails for large ones —
i.e. for some messages and not others.

With `d = 1` there is no tree index in the digest at all (`h - h/d = 0`), so
`128-24`'s ADRS carries eight constant zero bytes there and the emitter pushes
them as a literal rather than converting a runtime zero.

### 6.3 Witness encoding

A signature is 241 to 491 `n`-byte elements and `MAX_STACK_SIZE` is **244,
counting both stacks**. Elements cannot be pushed individually under any of the
three sets — `128-24`'s 241 elements are under the limit on their own, and then
are not once the verifier's working frame and the digest are on the stack with
them. Three elements of headroom is not a margin to build an address on.

The signature is pushed as blobs of 4 elements (`BLOB_ELEMS = 4`), in signature
order: **123 blobs** for `128s`, **61** for `128-24`, **97** for `128-24d2`.
The verifier's prologue moves them to the alt stack — which reverses them into a
queue — and slices each blob when reached, pushing its elements back above the
remaining blobs so they pop in order.

Cost model, verified against the engine: `OpSubstr` is charged only for the
substring it produces and inter-stack moves are free, but `OpSubstr` *consumes*
the blob, so each extraction needs an `OpDup` of the remainder. Extracting `e`
elements from one blob costs `16·e·(e+1)`; across `E` elements in blobs of `e`
that is `16·E·(e+1)` — **linear in blob size, not quadratic in the signature**.

`BLOB_ELEMS` is part of the redeem script and therefore part of the address.
Measured sweep, on `128s` — the set with the most elements to place, and so the
one the choice is bound by. **These are the bare verifier**, which takes its
message from the witness; a vault script is 42 bytes larger because it emits the
binding digest instead ([§11](#11-measured-costs) quotes the vault figure,
89,235):

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
H_msg       two SHA-256 calls -> an m-byte digest
indices     md, idx_tree, idx_leaf carved from digest
FORS        k trees x (1 leaf hash + a-node path), then T_k
hypertree   d layers x (len Winternitz chains + h'-node path)
epilogue    compare against the pinned PK.root
```

Per set, that is:

| | FORS | hypertree |
|---|---|---|
| `128s` | 14 × (1 + 12) | 7 × (35 chains + 9) |
| `128-24` | 6 × (1 + 24) | 1 × (68 chains + 22) |
| `128-24d2` | 15 × (1 + 14) | 2 × (68 chains + 12) |

`H_msg` for the SHA2 parameter sets is an inner SHA-256 followed by one
MGF1-SHA-256 block; `m` is 30, 21 or 24 and MGF1 emits 32 per block, so the
counter is always zero and the loop unrolls to nothing for every set.

The signed message is `M' = toByte(0,1) || toByte(|ctx|,1) || ctx || D`. The
vault uses an **empty context**, so the prefix is two zero bytes. Omitting them
produces a self-consistent scheme that no standards-conforming implementation
can verify.

Winternitz chain length depends on a message digit, so all `w - 1` steps are
emitted and gated on `digit <= step` — 15 under `128s`, 3 under the `w = 4`
sets. Untaken `OpIf` branches cost script *bytes* and zero script *units*, so a
spend pays worst-case size for average-case compute.

The WOTS+ checksum digits follow FIPS 205's shift-to-a-byte-boundary and
`base_2b` construction. Under `128s` the checksum spans 12 bits and its digits
are the nibbles of `csum << 4`; under the `w = 4` sets it spans 8 bits and its
four digits are 2-bit fields of `csum` itself. Reading the first as "take the
nibbles" and carrying that to the second gives a verifier that is
self-consistent and rejects every real signature.

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

An LM-OTS private key is `p` values and a signature is a partial opening of it.
One signature is safe because the checksum is self-limiting: raising a message
digit lowers the checksum, so forging would require walking a checksum chain
backwards, i.e. inverting a hash.

**Two signatures remove that protection.** They expose `min(a_i, b_i)` on every
chain, and walking a chain *forward* is free, so an attacker can grind for a
message whose digits dominate those minimums and whose checksum is consistent.
That mechanism is structural and not in dispute.

The *cost* of that grind depends on how far apart the two signatures' digits
fall. The figure usually quoted is **~2^34 hashes from two signatures**,
reported by the QRL project, which has run this construction in production
since 2018; it is an order-of-magnitude claim rather than a bound this project
has reproduced. Whatever the constant, it is small enough to treat two
signatures under one key as a loss of funds rather than a degradation.

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
sign anything that is not a transaction, use one of the SLH-DSA schemes.

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

All three SLH-DSA sets are NIST category 1. FIPS 205 approves `128s`; SP 800-208
has no category 1 parameter set for *stateful* hash-based signatures, which is
why stateful designs land at category 3. Whether a decade-scale vault should use
`192s` instead is [open](#10-open-questions).

**The three sets do not have equal standing, and the difference is not
cryptographic strength — it is who has analysed them.**

- `128s` is standardised. FIPS 205 states its security, and an independent
  implementation reproduces this one key-for-key.
- `128-24` comes from SP 800-230, an **initial public draft**. Its security
  analysis is NIST's, and its numbers can change before the document is final.
  If they do, addresses funded under it are spendable only by this code.
- `128-24d2` **has not been reviewed by any standards body**, and should not be
  described as though it had. What exists instead is arithmetic: the FORS
  multi-target forgery bound has been computed for it twice, independently, each
  derivation validated against SP 800-230's own published figure for `128-24`
  before being trusted ([§8.5.1](#851-computed-bounds)).

  Those bounds put it **at or above SP 800-230's category-1 variant** on every
  axis compared — 179.64 bits against 128.63 at the same 2^24 design point, a
  128-bit crossing at 2^29.25 signatures against roughly 2^24.1, and equal or
  better overuse tolerance at both the 100- and 80-bit thresholds.

  That is a computation of one term in a security argument, not a proof and not
  a review. It says the FORS parameters are not the weak point; it says nothing
  about the other terms, and nobody with authority over the standard has looked
  at this set. Note also that the comparison is to the **category-1** variant
  only — SP 800-230 also drafts `192-24` and `256-24`, which this set is nowhere
  near.

#### 8.5.1 Computed bounds

The FORS multi-target forgery bound (Fluhrer & Dang, eprint 2024/018, Eq. 1)
evaluated at each set's own design point. Two independent derivations agree to
the digit shown; both reproduce SP 800-230's published 112-bit overuse figure
for `128-24` (27.25, computed 27.2453) as a calibration check.

| | design point | bits there | falls below 128 bits at |
|---|--:|--:|--:|
| `128s` | 2^64 | 133.75 | — (at its limit) |
| `128-24` | 2^24 | 128.63 | ~2^24.1 |
| `128-24d2` | 2^24 | **179.64** | **2^29.25** ≈ 638 million |

`128-24d2` degrades from there as: 117.96 bits at 2^30, and around 0 bits at
2^40 — where forgery is more likely than not. Its crossings past the design
point are +7.28 doublings to 100 bits and +8.66 to 80 bits.

**The stated 2^24 limit is an operational cap, not the security floor.** It
matches the hypertree's capacity and is the number to publish; the bound does
not actually cross 128 bits until roughly 38x further out. The two should not be
conflated in either direction — the cap is what the set is *sized* for, and
`128-24`'s own margin above it is essentially nil.

These are **classical forgery-probability bounds** under the standard's `2^-n`
convention, not "post-quantum bits". A related question is settled by the same
arithmetic: category 1 is sometimes quoted as requiring ≥143 bits, which cannot
be the operative floor for this bound, since FIPS 205's own `128s` never exceeds
133.75. The 143-bit figure belongs to NIST's categorical gate-count argument,
not to this query-count one.

A constraint on any future re-sweep of `(a, k)`: `m` must stay at or under 32
bytes, or `H_msg` needs a second MGF1-SHA-256 block, which is an emitter change
rather than a constant change. At `a = 14` that caps `k` at 16. Several `(a, k)`
pairs that score better on the bound alone — `(11, 24)` and `(12, 20)` among
them — are past that wall and are not reachable by this emitter as written.

Both 2^24 sets also carry a limit `128s` does not: **2^24 signatures per key,
counting every signature, including ones the chain never sees**. For a vault
that limit is not reachable in any plausible lifetime — a spend a day exhausts
it in about 45,000 years — but it is a limit, and a key used as a general-purpose
signing key rather than as a vault could reach it. Nothing in this code counts
signatures or enforces the cap.

---

## 9. Reproducibility

A vault address is the hash of a script this workspace **compiles**. An
independent build that differs by one byte derives a different address from the
same mnemonic, and anyone funding it loses the coins with no error anywhere.

- `Cargo.lock` is committed; `oxicrypt-lms` is pinned exactly, and `fips205` —
  now a dev-dependency rather than something an address passes through — is
  pinned so the oracle cannot drift either.
- `rust-toolchain.toml` pins the compiler.
- Frozen vectors pin mnemonic → xi → public key → script hash → address for
  every scheme, and the binding digest independently.
- `kaspa-vault artifacts` prints every address-affecting value, derived from the
  published BIP39 test mnemonic. It takes no key material and touches no
  network. It skips `SLH-DSA-SHA2-128-24`'s key, whose 2^22 WOTS+ public keys
  put it at about a hundred seconds; `kaspa-vault slh-address --set 128-24`
  reproduces that one on demand, and its *script* — the part a build can change
  — is frozen and checked on every test run without a key at all.

Any difference in that output is a compatibility break.

What is **not** claimed is a bit-reproducible build in the
[reproducible-builds.org](https://reproducible-builds.org) sense: binaries have
not been compared across machines, and build paths, timestamps and locale are
uncontrolled. That property is not what an address needs. What it needs is that
the *emitted script* is deterministic given the same source, and that is pinned
above and checkable by anyone. The generator uses no floating point, no
iteration over unordered collections, and no compiler-version-dependent
behaviour; a directory rename was confirmed to leave every artifact byte
identical.

---

## 10. Open questions

**Multi-input.** Every redeem script assumes exactly one vault input, so UTXOs
cannot be consolidated: five received payments are five separate spends.
Fixing this means a different unrolled script and probably a distinct address
type.

**Security level.** `128s` (category 1) versus `192s` for a decade-scale vault,
against roughly double the on-chain cost. SP 800-230 proposes `192-24` and
`256-24` as well, on the same 2^24 trade as `128-24`; neither is implemented
here, and `192-24` is the obvious thing to measure next if category 3 is wanted.

**Whether either 2^24 set should be used at all.** `128-24` is a draft NIST may
still change, and `128-24d2` is nobody's proposal. They are implemented and
measured so the question can be answered with numbers rather than guesses; the
numbers say the on-chain saving is large ([§11](#11-measured-costs)) and say
nothing about whether the standards process will land where the draft is now.

**Whether `d = 1` is acceptable for a vault.** `128-24` costs about 100 seconds
to generate a key and 23 to sign, on six cores; a confirmed spend took 2m05s
wall clock. That is the draft's deliberate
trade for "sign-once, verify-many", and a vault signer is not a build server.
`128-24d2` prices the alternative, at bounds computed rather than reviewed
([§8.5](#85-security-level)).

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

### 11.1 Confirmed on-chain

Testnet-10, confirmed spends.

| | `128s` | `128-24` | `128-24d2` | LMS h=15 w=2 |
|---|--:|--:|--:|--:|
| redeem script | 89,235 B | 21,752 B | 33,664 B | 19,717 B |
| transaction | 97,472 B | 25,925 B | 40,193 B | 24,890 B |
| script units | 1,330,069 | 267,546 / 267,553 | 454,056 – 473,019 | 373,146 |
| compute budget | 136 → 142 | 29 | 48 / 50 / 48 | 40 |
| normalized mass | 194,944 | 51,850 | 80,386 | 49,780 |
| fee | 0.2339 TKAS | 0.0622 TKAS | 0.0965 TKAS | 0.0597 TKAS |
| fee floor | 0.1949 TKAS | 0.0519 TKAS | 0.0804 TKAS | 0.0498 TKAS |
| spends per block | 2 | 9 | 6 | ~10 |

Each set's unit counts are consecutive spends of the **same key**, each spending
the previous one's change. Chain length depends on the message digit, so the
count moves — which is why [§8.3](#83-compute-budget) requires the budget to come
from the signature being broadcast rather than from the parameter set.

**`128-24d2`'s three spends spanned 18,963 units (4.2%) and moved the declared
budget 48 → 50 → 48.** Earlier rounds suggested `w = 4` gave a much narrower band
than `128s`'s 136 → 142, since `128-24` held 29 and `128-24d2` held 43 at
`k = 11`. Those were two-sample observations. With `d·len = 136` chains of up to
three steps the spread is a few thousand units either way, so a tight pair was
luck, not structure. `BUDGET_MARGIN_UNITS = 2` absorbed the move here; it is not
guaranteed to.

`SLH-DSA-SHA2-128-24` is **cheaper to verify than LMS** — 267,546 units against
373,146 — at 1.04x its transaction bytes. That is a stateless post-quantum
signature costing about 4% more than a stateful one, on a live chain, with no
consensus change.

The measured figures agree with §11.2's harness numbers to within one
transaction byte and two units of normalized mass. That is the claim this
workspace is organised around — that a measurement against `TxScriptEngine` and
`MassCalculator` with a fabricated UTXO is the number a node will charge — and
it is now checked rather than assumed.

`128-24d2` also spent three times under an earlier `k = 11` FORS choice, at
34,751 transaction bytes against 34,752 predicted — the same agreement — before
a security review replaced that choice with `k = 15`
([§6.1](#61-parameters)). Those figures describe a set this document no longer
specifies and are not carried in the table above.

### 11.2 All four, measured in one process

Same spend shape (one input, two standard outputs), same `TxScriptEngine`, same
`MassCalculator` with testnet parameters, same funding amount. Nothing here is
quoted from a previous session, and the compute budget on every row is the one
that row's own signature needs:

| | stateful | signatures | redeem B | sigscript | tx bytes | units | norm mass | per block | fee TKAS |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| LMS h=15 w=2 | yes | 2^15 | 19,717 | 24,637 | 24,891 | 375,226 | 49,782 | 10 | 0.0498 |
| SLH-DSA-SHA2-128s | no | 2^64 | 89,235 | 97,219 | 97,473 | 1,285,456 | 194,946 | 2 | 0.1949 |
| SLH-DSA-SHA2-128-24 | no | 2^24 | 21,752 | 25,672 | 25,926 | 266,270 | 51,852 | 9 | 0.0519 |
| SLH-DSA-SHA2-128-24d2 | no | 2^24 | 33,664 | 39,940 | 40,194 | 455,267 | 80,388 | 6 | 0.0804 |

`SLH-DSA-SHA2-128-24` costs **1.04x LMS's transaction bytes and fewer script
units than LMS** — a stateless scheme at a stateful scheme's price. On this
chain, at these parameters, statelessness costs about 4%.

The redeem script falls further than the signature does: 4.1x against 2.0x. The
script is dominated by emitted Winternitz chain steps, `d·len·(w-1)` — **3,675**
for `128s`, **204** for `128-24`, **408** for `128-24d2` — so `lg(w)` moving from
4 to 2 is what moves the script, and it is paid for in `len`, i.e. in the
signature bytes the 2^24 limit had already bought back.

Transient mass dominates every row: a vault spend is large but cheap to verify,
so the honest optimisation target is script **bytes**, not script units.

### 11.3 Signer cost

Six cores, midstate precomputed once per key, leaves built in parallel.

| | keygen | signing | leaves per tree |
|---|--:|--:|--:|
| SLH-DSA-SHA2-128s | 0.08 s | 0.52 s | 512 |
| SLH-DSA-SHA2-128-24 | **~100 s** | **23 s** | 4,194,304 |
| SLH-DSA-SHA2-128-24d2 | 0.09 s | 0.20 s | 4,096 |
| LMS h=15 w=2 | 5.96 s | 0.02 s | 32,768 |

`128-24`'s column is `d = 1`, and it is the one axis on which it is the worst of
the four.

### 11.4 Confirmed transactions

```
scheme' = 2   4f4f96c2494d741b3cc0f30bde3a15faa956bbdfeed60ba184cbef185dc2cd6c
scheme' = 2   25a8dc25735ec649f3d99379f969c5c7761d8546514c783050b34c5ad6c8d3d4   spends the above's change
scheme' = 2   3197116e1b8008111b94fddc8595d35d0a79676dbbfb3696dc231427d6a60c54   funds a scheme' = 4 vault
scheme' = 3   7d74a4308bf2a7379fb3602ec947722eb890ba83f8e63347381aa7f7c7e89e45
scheme' = 3   586e6e019603a3eead40b924da31359146129af924c553e0f738ef86263cfe08   spends the above's change
scheme' = 4   1f890510e29a44d22cf5d29b60920c4fea7ce292a4eb752cf5dbc0d93c089df0
scheme' = 4   0aaaf1768c15515bfe20bad6a2324eeda4aac83bf0e4f94378a8e137f25af826   spends the above's change
scheme' = 4   18878fec837b47fec47140eb841f82c2d52b1451df41cc9a546ef0042f78dabe   and its change again
scheme' = 1   9df246be429549dfd7635f2c95c6fed580f491632db9ee5777a9fab22fce755a
scheme' = 1   7dd3834583a9b501f969420b4aff1b7ef6fe51b8151463ba30672fa2671e0a00
```

Each stateless run is one key signing several different messages from one
address, each spending the previous one's change. `scheme' = 4`'s three spends
are the longest such chain here, and the one where the compute budget moved
between them ([§11.1](#111-confirmed-on-chain)).

A further three `scheme' = 4` transactions exist under its earlier `k = 11`
FORS choice — `4a83c79e…`, `bf6c80e7…`, `da02dcc1…`, the last of which funded
the `scheme' = 3` vault above. They describe a set this document no longer
specifies.
