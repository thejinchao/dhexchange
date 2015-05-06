# Diffie–Hellman key exchange algorithm
a very simple 128bit Diffie–Hellman key exchange algorithm

## Build:
```
gcc test.c dhexchange.c -o test
./test
```
## About Diffie–Hellman key exchange

http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange


## How to use
(1) <b>Alice</b>: Generate private key and public key
```
DH_KEY alice_private, alice_public;
DH_generate_key_pair(alice_public, alice_private);
```
(2) <b>Bob</b>: Generate private key and public key
```
DH_KEY bob_private, bob_public;
DH_generate_key_pair(bob_public, bob_private);
```
(3) <b>Exchange</b>: Alice send her public key to Bob, and Bob send his public key to alice

(4) <b>Alice</b>: Generate secret key
```
DH_KEY alice_secret;
DH_generate_key_secret(alice_secret, alice_private, bob_public);
```
(5) <b>Bob</b>: Generate secret key
```
DH_KEY bob_secret;
DH_generate_key_secret(bob_secret, bob_private, alice_public);
```
