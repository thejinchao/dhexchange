# Diffie–Hellman key exchange algorithm
a very simple 128bit Diffie–Hellman key exchange algorithm

## Build:
```
gcc test.c dhexchange.c -o test
./test
```
the result looks like:
```
alice_private=  21020c4a4c949fd14d0cf2a2402f2aff
alice_public=   500c1bdba67f00684715fa5cdaf82724
bob_private=    ad7521da95e27fc1e96c4bcda7e650b6
bob_public=     c3e1e42bcb39d2f64b4c222fc6510801
alice_secret=   c5156ec39e8bb1e7940f8dbfd53fd89c
bob_secret=     c5156ec39e8bb1e7940f8dbfd53fd89c
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
