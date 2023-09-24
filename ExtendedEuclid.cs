using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            // declare all variables needed 
            int A1 = 1, A2 = 0, A3 = baseN, B1 = 0, B2 = 1, B3 = number;
            int q, temp_A1, temp_A2, temp_A3;
            // compute each row in the table and ignore previous row to save memory useage 
            while (true)
            {
                q = A3 / B3;
                temp_A1 = A1 - (q * B1);
                temp_A2 = A2 - (q * B2);
                temp_A3 = A3 - (q * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = temp_A1;
                B2 = temp_A2;
                B3 = temp_A3;
                // if we find B3 = 0 or 1  this means we finish 
                if (B3 == 1) // if B3 == 1 this means B2 is the Multiplicative Inverse 
                {
                    if (B2 < 0)
                    {
                        B2 += baseN;
                    }
                    return B2;
                }
                else if (B3 == 0) // if B3 == 0 this means  that there is no Multiplicative Inverse and return -1
                {
                    return -1;
                }

            }

        }
    }
}

