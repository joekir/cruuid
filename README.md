# cruuid

_en**cr**ypted **uuid**_

A random little script that can encrypt small amounts of data into a UUIDv4 format.
This is more fiddlesome than might first appear due to blocksize limitation of
"_good_" symmetric ciphers.

The approach was to use [Triple-DES](https://en.wikipedia.org/wiki/Triple_DES)
as it's blocksize is only 64 bits, using [CFB mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB))
avoids the need to pad to the blocksize to also save space.

Finally a truncated (variable based on ciphertext length) HMAC_SHA256 of the data
is computed to provide some integrity to this (pretty weak) ciphersuite selection.

### Usage

```bash
$ pipenv install
$ pipenv shell

(cruuid) bash$ ./cruuid.py encrypt -d foo

Please save this composite encryption key:
d023a20bc2e97c072aae61640d9252ae265ef1541f8abf52520b9f6095eb54b96ea6a8b7e057ba7a577a02d09c0c04b0983cfea567ec392a

UUIDv4: 489c0e42-05c3-4e7a-6942-93605c70e031

(cruuid) bash$ ./cruuid.py decrypt -u 489c0e42-05c3-4e7a-6942-93605c70e031 -k d023a20bc2e97c072aae61640d9252ae265ef1541f8abf52520b9f6095eb54b96ea6a8b7e057ba7a577a02d09c0c04b0983cfea567ec392a
b'foo'
```