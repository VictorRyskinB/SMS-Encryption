Project for cryptology course. developed as a duo.
# SMS Encryption

A simulation of end-to-end encrypted SMS between two phone users (Alice and Bob) through a phone operator. Built as a duo project for a cryptology course.

## How it works

- **Key exchange:** Diffie–Hellman over the 2048-bit MODP group (RFC 3526). Each pair of users derives a shared secret, which is hashed with SHA-256 into a 128-bit key.
- **Encryption:** XTEA in OFB mode with a random IV per message and PKCS#7-style padding.
- **Signatures:** Elliptic-curve signatures (ECDSA-style) on the NIST P-224 curve, implemented from scratch, so the recipient can check who sent each message.
- **Operator:** keeps a directory of users' public keys. Users look up a contact's keys there and never share private keys.
- **Public airwaves:** every ciphertext "sent over the air" is appended to `publicLogs.txt`, so you can see what an eavesdropper would capture.

## Files

| File | Description |
|------|-------------|
| `Main.py` | Operator and User classes, plus a demo chat between Alice and Bob |
| `XTEA_DH.py` | Diffie–Hellman key exchange and XTEA encryption; runs its own demo when executed directly |
| `EC_El_Gamal.py` | Elliptic-curve arithmetic, key generation, and message signing and verification |
| `publicLogs.txt` | Log of encrypted messages as seen on the public channel |

## Running

Requires Python 3 and only the standard library.

```bash
python Main.py
```

The demo prints each step in color: keys, ciphertexts, and signature values. You can also run `python XTEA_DH.py` on its own to see just the DH and XTEA flow.

## Disclaimer

This is an educational project and is not secure for real use. It uses Python's `random` module instead of a cryptographically secure RNG, hand-written crypto primitives, and debug output that prints private keys.
