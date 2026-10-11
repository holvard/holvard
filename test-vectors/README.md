# Holvard test vectors

Sample cards and vaults with expected results, used by `holvard-core`, the
recovery page and any other implementation to check compatibility.

Dedicated to the public domain under [CC0 1.0](../LICENSES/CC0-1.0.txt),
except `slip39/vectors.json` and `slip39/wordlist.txt`.

## slip39/

Trezor's SLIP-39 reference test vectors and the SLIP-39 wordlist, copied
byte for byte from
[python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic)
under its [MIT licence](../LICENSES/MIT.txt) (2019 SatoshiLabs). Holvard's
SLIP-39 implementation must pass every vector. `slip39/SOURCE` records the
upstream commit and hashes; CI checks the copies against it on every run and
against upstream weekly.
