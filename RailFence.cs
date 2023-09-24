using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            //init var
            string p = plainText;
            string c = cipherText;

            //convert P.T & C.T to be able to compare them
            p = p.ToLower();
            c = c.ToLower();
           
            //begin key = 1 not 0 (0*num = 0)
            for (int key = 1; key < p.Length; key++)
            {
                // remember window size, how many characters to jump
                if (p[key] == c[1])
                {
                    if (p[key * 2] == c[2])
                    {
                        if (p[key * 3] == c[3])
                        {
                            return key;
                        }
                    }
                }
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();

            //init values
            string P_T = "";
            int Count1 = 0;

            //calculate the num of columns 
            //apply celiling
            int Coulmns = (cipherText.Length + key - 1) / key;

            //loop on the columns
            while (Count1 < Coulmns)
            {
                //save it's value before make any change on it
                int Count2 = Count1;

                //loop on the keys(depth) to full the columns
                for (int i = 0; i < key; i++)
                {
                    // check if count over the C.T length
                    if (Count1 >= cipherText.Length)
                    {
                        //if the cond right break from the loop because the column is full in this case
                        break;
                    }
                    //add the chars in the P.T
                    P_T += cipherText[Count1];
                    Count1 += Coulmns;
                }
                //++ the outer counter
                Count1 = Count2 + 1;
            }

            //finally return the P.T
            return P_T;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();

            //init values
            string C_T = "";
            int Count1 = 0, Count2 =  0;

            //loop on the plaintext
            for (int i = 0; i < plainText.Length; i++)
            {
                //check if the count1 over the P.T length
                if (Count1 >= plainText.Length)
                {
                    //Count2++ & loop on the other indexes
                    Count2++;
                    Count1 = Count2;
                }
                //add every char in the C.T
                C_T += plainText[Count1];
                Count1 += key;
            }
            //finally return the cipher text
            return C_T;
        }
    }
}
