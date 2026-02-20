# Third-Party Licenses

This file lists the licenses of third-party dependencies used by Wallet Recovery CLI.

## Direct Dependencies

| Module | Version | License | Link |
|--------|---------|---------|------|
| github.com/google/uuid | v1.6.0 | MIT | https://github.com/google/uuid/blob/main/LICENSE |
| github.com/mr-tron/base58 | v1.2.0 | MIT | https://github.com/mr-tron/base58/blob/master/LICENSE |
| github.com/spf13/cobra | v1.9.1 | Apache-2.0 | https://github.com/spf13/cobra/blob/main/LICENSE.txt |
| github.com/spf13/viper | v1.20.1 | MIT | https://github.com/spf13/viper/blob/master/LICENSE |
| golang.org/x/crypto | v0.41.0 | MIT | https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.41.0:LICENSE |
| golang.org/x/term | v0.34.0 | MIT | https://cs.opensource.google/go/x/term/+/refs/tags/v0.34.0:LICENSE |
| filippo.io/edwards25519 | v1.1.0 | MIT | https://github.com/FiloSottile/edwards25519/blob/main/LICENSE |
| github.com/ethereum/go-ethereum | v1.16.8 | LGPL-3.0 | https://github.com/ethereum/go-ethereum/blob/master/COPYING.LESSER |
| gitlab.com/Blockdaemon/go-tsm-sdkv2/v70 | v70.1.0 | Apache-2.0 | https://gitlab.com/Blockdaemon/go-tsm-sdkv2 |
| github.com/consensys/gnark-crypto | v0.18.1 | Apache-2.0 | https://github.com/Consensys/gnark-crypto/blob/master/LICENSE |
| github.com/decred/dcrd/dcrec/secp256k1/v4 | v4.4.0 | ISC | https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/LICENSE |
| github.com/gtank/merlin | v0.1.1 | MIT | https://github.com/gtank/merlin/blob/master/LICENSE |
| github.com/gtank/ristretto255 | v0.1.2 | MIT | https://github.com/gtank/ristretto255/blob/master/LICENSE |
| github.com/holiman/uint256 | v1.3.2 | MIT | https://github.com/holiman/uint256/blob/master/LICENSE |
| github.com/mimoo/StrobeGo | v0.0.0-20220103164710-9a04d6ca976b | Apache-2.0 | https://github.com/mimoo/StrobeGo/blob/master/LICENSE |
| github.com/gorilla/mux | v1.8.1 | MIT | https://github.com/gorilla/mux/blob/master/LICENSE |
| github.com/bits-and-blooms/bitset | v1.22.0 | MIT | https://github.com/bits-and-blooms/bitset/blob/master/LICENSE |
| go.uber.org/multierr | v1.11.0 | MIT | https://github.com/uber-go/multierr/blob/master/LICENSE.txt |
| github.com/ProjectZKM/Ziren | v0.0.0-20251001021608-1fe7b43fc4d6 | Apache-2.0, MIT | https://github.com/ProjectZKM/Ziren/blob/main/LICENSE-APACHE |

## Key Transitive Dependencies

| Module | Version | License | Link |
|--------|---------|---------|------|
| github.com/spf13/pflag | v1.0.6 | MIT | https://github.com/spf13/pflag/blob/master/LICENSE |
| github.com/spf13/afero | v1.14.0 | Apache-2.0 | https://github.com/spf13/afero/blob/master/LICENSE |
| github.com/spf13/cast | v1.7.1 | MIT | https://github.com/spf13/cast/blob/master/LICENSE |
| github.com/go-viper/mapstructure/v2 | v2.4.0 | MIT | https://github.com/go-viper/mapstructure/blob/master/LICENSE |
| github.com/pelletier/go-toml/v2 | v2.2.4 | MIT | https://github.com/pelletier/go-toml/blob/master/LICENSE |
| github.com/sagikazarmark/locafero | v0.9.0 | MIT | https://github.com/sagikazarmark/locafero/blob/main/LICENSE |
| github.com/sourcegraph/conc | v0.3.0 | MIT | https://github.com/sourcegraph/conc/blob/main/LICENSE |
| github.com/subosito/gotenv | v1.6.0 | MIT | https://github.com/subosito/gotenv/blob/master/LICENSE |
| github.com/fsnotify/fsnotify | v1.9.0 | MIT | https://github.com/fsnotify/fsnotify/blob/main/LICENSE |
| go.uber.org/atomic | v1.7.0 | MIT | https://github.com/uber-go/atomic/blob/master/LICENSE.txt |
| golang.org/x/sync | v0.16.0 | MIT | https://cs.opensource.google/go/x/sync/+/refs/tags/v0.16.0:LICENSE |
| golang.org/x/sys | v0.36.0 | MIT | https://cs.opensource.google/go/x/sys/+/refs/tags/v0.36.0:LICENSE |
| golang.org/x/text | v0.28.0 | MIT | https://cs.opensource.google/go/x/text/+/refs/tags/v0.28.0:LICENSE |
| gopkg.in/yaml.v3 | v3.0.1 | MIT | https://github.com/go-yaml/yaml/blob/v3/LICENSE |

---

## License Compatibility

All dependencies are compatible with the Apache 2.0 license of this project:

- **MIT License**: Fully compatible with Apache 2.0
- **Apache-2.0 License**: Same as project license
- **ISC License**: Fully compatible with Apache 2.0
- **LGPL-3.0 License**: Compatible (go-ethereum is used as a library)

## Notes

- This project uses `go.mod` for dependency management
- All versions are pinned in `go.mod` for reproducible builds
- Some dependencies have transitive dependencies not listed here; see `go.mod` for the complete dependency tree
- For the most up-to-date license information, refer to each dependency's repository

