#ifndef DIFFIE_HELLMAN_EXCHANGE_H
#define DIFFIE_HELLMAN_EXCHANGE_H

#define DH_KEY_LENGTH	(16)

typedef unsigned char DH_KEY[DH_KEY_LENGTH];

void DH_generate_key_pair(DH_KEY public_key, DH_KEY private_key);
void DH_generate_key_secret(DH_KEY secret_key, const DH_KEY my_private, const DH_KEY another_public);

#endif
