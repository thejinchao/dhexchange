#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>
#include "dhexchange.h"

/*--------------------------------------------------------------------------*/
static void
_print_key(const char* name, const DH_KEY key) {
	int i;

	printf("%s=\t", name);
	for (i = DH_KEY_LENGTH-1; i>=0; i--) {
		printf("%02x", key[i]);
	}
	printf("\n");
}

/*--------------------------------------------------------------------------*/
int 
main(int argc, char* argv[])
{
	DH_KEY alice_private, bob_private;
	DH_KEY alice_public, bob_public;
	DH_KEY alice_secret, bob_secret;

	time_t seed;
	time(&seed);
	srand((unsigned int)seed);

	/*Alice generate her private key and public key */
	DH_generate_key_pair(alice_public, alice_private);

	/*Bob generate his private key and public key */
	DH_generate_key_pair(bob_public, bob_private);

	/*Bob send his public key to Alice, Alice generate the secret key */
	DH_generate_key_secret(alice_secret, alice_private, bob_public);

	/*Alice send her public key to Bob, Bob generate the secret key */
	DH_generate_key_secret(bob_secret, bob_private, alice_public);

	_print_key("alice_private", alice_private);
	_print_key("alice_public", alice_public);
	_print_key("bob_private", bob_private);
	_print_key("bob_public", bob_public);
	_print_key("alice_secret", alice_secret);
	_print_key("bob_secret", bob_secret);

	if (memcmp(alice_secret, bob_secret, DH_KEY_LENGTH) != 0) {
		printf("ERROR!\n");
		return 1;
	}

	return 0;
}