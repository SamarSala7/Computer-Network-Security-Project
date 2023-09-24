using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            int K = modular_pow(y, k, q);
            List<long> C = new List<long>();
            C.Add((long)modular_pow(alpha, k, q));
            long c2 = (K * m) % q;
            while (c2 < 0) { c2 += q; };
            C.Add(c2);
            return C;

        }
        public int modular_pow(int b, int exponent, int modulus)
        {
            int c = 1;

            for (int i = 1; i <= exponent; i++)
            {
                c = (c * b) % modulus;
            }
            return c;
        }
        static int modInverse(int a, int Mod)
        {
            int M = Mod, K = 0, d = 1;
            while (a > 0)
            {
                int t = M / a, x = a;
                a = M % x;
                M = x;
                x = d;
                d = K - t * x;
                K = x;
            }
            K %= Mod;
            while (K < 0)
                K = (K + Mod) % Mod;
            return K;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            int K = modular_pow(c1, x, q);
            int inverse = modInverse(K, q);
            int res = (c2 * inverse) % q;
            return res;

        }
    }
}
