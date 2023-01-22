# libunrealpak

`libunrealpak` is yet another Rust library for reading and writing Unreal Engine 4 `.pak` archives.

The goal of this library is to support these key use cases:

- Reading a `.pak` archive to extract its metadata without reading the actual assets.
- Unpacking a `.pak` archive.
- Packing a `.pak` archive given a directory tree of assets.

## Related Projects

- [bananaturtlesandwich/unpak](https://github.com/bananaturtlesandwich/unpak) and its fork
  [trumank/unpak](https://github.com/trumank/unpak)
- [panzi/rust-u4pak](panzi/rust-u4pak)
- [Speedy37/ue4pak-rs](https://github.com/Speedy37/ue4pak-rs)
- [AstroTechies/unrealmodding](https://github.com/AstroTechies/unrealmodding/tree/main/unreal_pak)
- [rust-unreal-unpak](https://crates.io/crates/rust-unreal-unpak)
