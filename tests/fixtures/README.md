# External ML-DSA-65 verification vectors

`mldsa_65_verify_test.json` is an unmodified snapshot from
[C2SP/Wycheproof](https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/mldsa_65_verify_test.json),
retrieved 2026-10-10. It contains 210 valid/invalid verification cases, including
repeated hint indices, incorrect lengths, modified signatures and invalid contexts.
Apply them according to the [upstream ML-DSA vector documentation](https://github.com/C2SP/wycheproof/blob/main/doc/mldsa.md).

The upstream project distributes these vectors under Apache-2.0. See its
[license](https://github.com/C2SP/wycheproof/blob/main/LICENSE) for copyright and terms.
External vectors test implementation behavior; they do not establish a protocol
audit, independent backend comparison or side-channel resistance.

Snapshot SHA-256: `49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02`. The upstream license is preserved in `LICENSE.wycheproof`.
