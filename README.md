# zig-discv5

Pure Zig implementation of the Ethereum [**Node Discovery Protocol v5**](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) (discv5). The goal is a small, dependency-free library suitable for embedding in clients and tooling.

## Status

The layout is modular; several areas are still stubs (`NotImplemented`) while primitives land first.

| Area | Module | Notes |
|------|--------|--------|
| Shared errors | `errors` | Common error sets |
| Varint | `varint` | Unsigned LEB128 (`u64`), minimal encoding, strict decode |
| RLP | `rlp` | Strings and lists for devp2p payloads |
| Wire | `wire` | `MessageKind`, `varint`, `packet`, `message`, `message_crypto` |
| Message | `message` | Ordinary message RLP encode/decode; REGTOPIC/TICKET/REGCONFIRMATION/TOPICQUERY (0x07–0x0a) decode only when `-Dexperimental_topic_wire=true` (default). Encode helpers always exist for tooling. |
| Message crypto | `message_crypto` | AES-128-GCM for ordinary message ciphertext (spec section 2.3) |
| ENR | `enr` | EIP-778 textual `enr:` decode (base64url + RLP layout checks) |
| Handshake | `handshake` (alias `crypto`) | HKDF session keys, identity-proof SHA-256 |
| Identity v4 | `identity_v4` | Compressed pubkey, ECDH (`eph`), ECDSA identity proof (64-byte raw signature) |
| Packet | `packet` | UDP bounds, header unmask, static header + auth layouts |
| Routing | `routing` | Kademlia table: 256 buckets (k=16), per-bucket replacement cache, LRU/MRU, closest + FINDNODE export |
| Session | `session` | LRU session table (node id + UDP endpoint), cached keys, GCM nonce helper |
| Topic | `topic` | Topic table per discv5-theory: FIFO queues, per-topic and global caps, `target_ad_lifetime` purge, registration wait hints |
| Node | `node` | Local node runtime (stub) |

## Requirements

- [Zig](https://ziglang.org/) **0.16.0** or newer (see `build.zig.zon`).

## Versioning

This package follows [Semantic Versioning](https://semver.org/). The current version is declared in `build.zig.zon` (`version` field) and should be bumped on release.

## Build and test

```sh
zig build test
zig fmt --check .
```

Build option (non-final [topic advertisement](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) wire):

```sh
zig build test -Dexperimental_topic_wire=false
```

## Use as a dependency

Add `zig_discv5` as a path or URL dependency in your `build.zig.zon`, then import the module in `build.zig`:

```zig
const discv5 = b.dependency("zig_discv5", .{
    .target = target,
    .optimize = optimize,
}).module("zig_discv5");
```

Exact `dependency` shape depends on whether you consume the package from a git URL, tarball, or local path.

## Continuous integration

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — on pushes and PRs to `main`: format check, `zig build test`, and the same tests with `-Dexperimental_topic_wire=false`.

## Releases

Manual release (creates a GitHub Release and tag at the current commit):

1. Ensure `version` in `build.zig.zon` matches the tag without the `v` prefix (e.g. tag `v0.1.0` ↔ version `0.1.0`).
2. Actions → **Release** → **Run workflow** → set tag (default `v0.1.0`).

Workflow: [`.github/workflows/release.yml`](.github/workflows/release.yml).

## Specification

- [discv5.md](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) — overview  
- [discv5-wire.md](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md) — wire encoding  
- [discv5-theory.md](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md) — algorithms  

## Repository

https://github.com/ch4r10t33r/zig-discv5
