using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

class DHExchange
{
    public static readonly int DH_KEY_LENGTH = 16;

    /* P =  2^128-159 = 0xffffffffffffffffffffffffffffff61 (The biggest 64bit prime) */
    private static readonly UInt128 P = new UInt128(0xffffffffffffff61, 0xffffffffffffffff);
    private static readonly UInt128 INVERT_P = new UInt128(159, 0);
    private static readonly UInt128 G = new UInt128(5, 0);

    private struct UInt128
    {
        UInt64 _low;
        UInt64 _high;

        public UInt128(UInt64 l, UInt64 h)
        {
            _low = l; _high = h;
        }
        public UInt128(UInt128 other)
        {
            _low = other._low; _high = other._high;
        }
        public UInt128(byte[] bytes)
        {
            _low = _high = 0;
            for (int i = 0; i < 8; i++)
            {
                _low = _low | (((UInt64)bytes[i]) << (i * 8));
                _high = _high | (((UInt64)bytes[i + 8]) << (i * 8));
            }
        }
        public void to_bytes(byte[] bytes)
        {
            for (int i = 0; i < 8; i++)
            {
                bytes[i] = (byte)((_low >> (i * 8)) & 0xFF);
                bytes[i + 8] = (byte)((_high >> (i * 8)) & 0xFF);
            }
        }

        public bool is_zero()
        {
            return _low == 0 && _high == 0;
        }

        public bool is_odd()
        {
            return (_low & 1) != 0;
        }

        public void lshift()
        {
            UInt64 t = (_low >> 63) & 1;
            _high = (_high << 1) | t;
            _low = _low << 1;
        }

        public void rshift()
        {
            UInt64 t = (_high & 1) << 63;
            _high = _high >> 1;
            _low = (_low >> 1) | t;
        }
        public static int compare(UInt128 a, UInt128 b)
        {
            if (a._high > b._high) return 1;
            else if (a._high == b._high)
            {
                if (a._low > b._low) return 1;
                else if (a._low == b._low) return 0;
                else return -1;
            }
            else
                return -1;
        }

        public static UInt128 add(UInt128 a, UInt128 b)
        {
            UInt64 overflow = 0;
            UInt64 l = a._low + b._low;
            if (l < a._low || l < b._low)
            {
                overflow = 1;
            }
            return new UInt128(l, a._high + b._high + overflow);
        }

        public static UInt128 add_i(UInt128 a, UInt64 b)
        {
            UInt64 overflow = 0;
            UInt64 l = a._low + b;
            if (l < a._low || l < b)
            {
                overflow = 1;
            }

            return new UInt128(l, a._high + overflow);
        }

        public static UInt128 sub(UInt128 a, UInt128 b)
        {
            UInt128 invert_b = new UInt128(~b._low, ~b._high);
            invert_b = add_i(invert_b, 1);
            return add(a, invert_b);
        }

        /*--------------------------------------------------------------------------*/
        /* r = a*b mod P */
        public static UInt128 _mulmodp(UInt128 _a, UInt128 _b)
        {
            UInt128 r = new UInt128(0, 0);
            UInt128 a = new UInt128(_a);
            UInt128 b = new UInt128(_b);

            while (!b.is_zero())
            {
                if (b.is_odd())
                {
                    UInt128 t = sub(P, a);

                    if (compare(r, t) >= 0)
                    {
                        r = sub(r, t);
                    }
                    else
                    {
                        r = add(r, a);
                    }
                }
                UInt128 double_a = new UInt128(a);
                double_a.lshift();

                UInt128 P_a = sub(P, a);

                if (compare(a, P_a) >= 0)
                {
                    a = add(double_a, INVERT_P);
                }
                else
                {
                    a = double_a;
                }
                b.rshift();
            }

            return r;
        }

        /*--------------------------------------------------------------------------*/
        /* r = a^b mod P (reduce) */
        public static UInt128 _powmodp_r(UInt128 a, UInt128 b)
        {
            UInt128 half_b = new UInt128(b);

            if (b._high == 0 && b._low == 1)
            {
                return new UInt128(a);
            }

            half_b.rshift();

            UInt128 t = _powmodp_r(a, half_b);
            t = _mulmodp(t, t);

            if (b.is_odd())
            {
                t = _mulmodp(t, a);
            }
            return t;
        }

        /*--------------------------------------------------------------------------*/
        /* r = a^b mod P */
        public static UInt128 _powmodp(UInt128 _a, UInt128 b)
        {
            UInt128 a = new UInt128(_a);
            if (compare(a, P) > 0)
                a = sub(a, P);

            return _powmodp_r(a, b);
        }
    };

    /*--------------------------------------------------------------------------*/
    public static void generate_key_pair(byte[] public_key, byte[] private_key)
    {
        if (public_key == null || public_key.Length != DH_KEY_LENGTH) return;
        if (private_key == null || private_key.Length != DH_KEY_LENGTH) return;

        Random rand = new Random();

        /* generate random private key */
        for (int i = 0; i < DH_KEY_LENGTH; i++)
        {
            private_key[i] = (byte)(rand.Next() & 0xFF);
        }

        /* pub_key = G^prv_key mod P*/
        UInt128 private_k = new UInt128(private_key);
        UInt128 public_k = UInt128._powmodp(G, private_k);

        public_k.to_bytes(public_key);
    }

    /*--------------------------------------------------------------------------*/
    public static byte[] generate_key_secret(byte[] my_private, byte[] another_public)
    {
        if (my_private == null || my_private.Length != DH_KEY_LENGTH) return null;
        if (another_public == null || another_public.Length != DH_KEY_LENGTH) return null;

        UInt128 private_k = new UInt128(my_private);
        UInt128 another_k = new UInt128(another_public);

        /* secret_key = other_key^prv_key mod P*/
        UInt128 secret_k = UInt128._powmodp(another_k, private_k);
        byte[] secret_key = new byte[DH_KEY_LENGTH];
        secret_k.to_bytes(secret_key);
        return secret_key;
    }
}
