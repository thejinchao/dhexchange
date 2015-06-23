using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

class Program
{
    /*--------------------------------------------------------------------------*/
    public static void _print_key(String name, byte[] key)
    {
        int i;

        System.Console.Write("{0}=\t", name);
        for (i = DHExchange.DH_KEY_LENGTH - 1; i >= 0; i--)
        {
            System.Console.Write("{0:x2}", key[i]);
        }
        System.Console.WriteLine("");
    }

    static void Main(string[] args)
    {
        byte[] alice_private = new byte[DHExchange.DH_KEY_LENGTH];
        byte[] bob_private = new byte[DHExchange.DH_KEY_LENGTH];

        byte[] alice_public = new byte[DHExchange.DH_KEY_LENGTH];
        byte[] bob_public = new byte[DHExchange.DH_KEY_LENGTH];

        /*Alice generate her private key and public key */
        DHExchange.generate_key_pair(alice_public, alice_private);

        /*Bob generate his private key and public key */
        DHExchange.generate_key_pair(bob_public, bob_private);

        /*Bob send his public key to Alice, Alice generate the secret key */
        byte[] alice_secret = DHExchange.generate_key_secret(alice_private, bob_public);

        /*Alice send her public key to Bob, Bob generate the secret key */
        byte[] bob_secret = DHExchange.generate_key_secret(bob_private, alice_public);

        _print_key("alice_private", alice_private);
        _print_key("alice_public", alice_public);
        _print_key("bob_private", bob_private);
        _print_key("bob_public", bob_public);
        _print_key("alice_secret", alice_secret);
        _print_key("bob_secret", bob_secret);
    }
}
