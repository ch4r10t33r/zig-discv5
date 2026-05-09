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
| Message | `message` | Ordinary message RLP encode/decode (ping/pong/findnode/nodes/talk) |
| Message crypto | `message_crypto` | AES-128-GCM for ordinary message ciphertext (spec section 2.3) |
| ENR | `enr` | EIP-778 textual `enr:` decode (base64url + RLP layout checks) |
| Handshake | `handshake` (alias `crypto`) | HKDF session keys, identity-proof SHA-256 |
| Identity v4 | `identity_v4` | Compressed pubkey, ECDH (`eph`), ECDSA identity proof (64-byte raw signature) |
| Packet | `packet` | UDP bounds, header unmask, static header + auth layouts |
| Routing | `routing` | Kademlia table: XOR / log distance, 256 buckets, k=16, LRU/MRU, closest + FINDNODE bucket export |
| Topic | `topic` | Topic ads / search (stub) |
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

GitHub Actions runs `zig fmt --check .` and `zig build test` on pushes and pull requests.

## Specification

- [discv5.md](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) — overview  
- [discv5-wire.md](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md) — wire encoding  
- [discv5-theory.md](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md) — algorithms  

## Repository

https://github.com/ch4r10t33r/zig-discv5
