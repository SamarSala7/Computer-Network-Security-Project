using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public int modular_pow(int b, int exponent, int modulus)
        {
            int c = 1;

            for (int i = 1; i <= exponent; i++)
            {
                c = (c * b) % modulus;
            }
            return c;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            // throw new NotImplementedException();
            int yA = modular_pow(alpha, xa, q);
            int yB = modular_pow(alpha, xb, q);
            List<int> keys = new List<int>();
            keys.Add(modular_pow(yB, xa, q));
            keys.Add(modular_pow(yA, xb, q));
            return keys;
        }
    }
}
