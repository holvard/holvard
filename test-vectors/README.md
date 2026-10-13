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

## vault/

A vault made only with the official tools, following
[spec/vault.md](../spec/vault.md). Every implementation must open
`vault.age` with any two of the three cards and get `contents.txt` back.

| File | What it is |
|---|---|
| `secret.hex` | The secret, 32 random bytes as lowercase hex |
| `cards.txt` | Three SLIP-39 cards, one per line, 2 of 3 needed |
| `contents.txt` | The vault's contents |
| `vault.age` | `contents.txt` encrypted with age, passphrase `secret.hex` |

Made with `shamir-mnemonic` 0.3.0 and age 1.3.1:

```sh
openssl rand -hex 32 > secret.hex
shamir create 2of3 -S "$(cat secret.hex)"     # cards.txt: the three cards
AGE_PASSPHRASE_FD=3 age -e -j batchpass -o vault.age contents.txt 3<secret.hex
```

`shamir create` uses its defaults: iteration exponent 0, extendable
backup flag set, empty passphrase. age uses its default scrypt work
factor, 18.
