# idb-rs

A parser for IDA `IDB` and `TIL` files.

Special thanks to [Willi Ballenthin] and [willem] for IDB format research:
 - https://github.com/williballenthin/python-idb
 - https://github.com/nlitsme#ida

## Overview

TODO

## Documentation

IDB file format documentation: [fileformat.md](doc/fileformat.md).

## SDK compatibility layer

The crate implement a few functions in a similar way to original API: [sdk_comp.md](doc/sdk_comp.md).

## License

This plugin is released under the Apache-2.0 license.

### Dependency Licenses

Dependency licenses can be found [here](https://nightly.link/Vector35/idb-rs/workflows/CI.yaml/main/license). The list is generated in CI using [cargo-about].

[Willi Ballenthin]:https://github.com/williballenthin
[willem]:https://github.com/nlitsme
[cargo-about]:https://github.com/EmbarkStudios/cargo-about/
