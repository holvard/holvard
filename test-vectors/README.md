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

## vault-zip/

A vault whose contents are a zip of a folder, as `holvard create` makes
them, but made only with standard tools. Every implementation must open
`vault.age` with any two of the three cards and get `folder.zip` back;
unpacking it gives the folder `letters/`.

| File | What it is |
|---|---|
| `secret.hex` | The secret, 32 random bytes as lowercase hex |
| `cards.txt` | Three SLIP-39 cards, one per line, 2 of 3 needed |
| `folder.zip` | The contents: `letters/` zipped with `zip -X -r` (no extra fields) |
| `vault.age` | `folder.zip` encrypted with age, passphrase `secret.hex` |
| `with-extras.zip` | The same folder zipped with plain `zip -r`, which adds extra fields (Unix times, uid and gid); readers must accept it |

`letters/read-me-first.txt` holds `For my people.` and
`letters/notes/keys.txt` holds `The spare key is with the neighbour.`, each
followed by a newline.

SHA-256:

```text
f66e87a1e46a93ba2db43d55fdd5160538e4dd417e68500e67982d133a9787d6  folder.zip
5741b5599ffc2eaa512d5c821760607f87fabee71647b330aec4fb59719e3a2b  vault.age
453d385669c0fb8b1eebcfeb95e65f23bd1175383e1909ae57cdb2c0e26af8fe  with-extras.zip
```

Made with `shamir-mnemonic` 0.3.0, age 1.3.1 and Info-ZIP Zip 3.0. Fixed
file times and `TZ=UTC` make `folder.zip` byte-for-byte reproducible; the
vault and cards are random each time.

```sh
mkdir -p letters/notes
printf 'For my people.\n' > letters/read-me-first.txt
printf 'The spare key is with the neighbour.\n' > letters/notes/keys.txt
TZ=UTC touch -t 202601010000 letters letters/* letters/notes letters/notes/*
TZ=UTC zip -X -r folder.zip letters
TZ=UTC zip -r with-extras.zip letters
openssl rand -hex 32 | tr -d '\n' > secret.hex
shamir create 2of3 -S "$(cat secret.hex)"     # cards.txt: the three cards
AGE_PASSPHRASE_FD=3 age -e -j batchpass -o vault.age folder.zip 3<secret.hex
```
