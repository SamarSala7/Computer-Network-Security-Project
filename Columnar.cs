using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            //init the key
            List<int> key = new List<int>();
            //convert P.T & C.T into lowercase
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //init var L (length of the key)
            int L = 0;
            //init KeyMax 
            int KeyMax = plainText.Max();
            //init P.T Length
            int P_TLength = plainText.Length;
            //loop on KeyMax
            for (int i = 0; i < KeyMax; i++){
                //Ex:(Samar Salah) L = 10 ,key = 132, i = 3
                //first column index 0 , 3 , 6
                string S1 = plainText[0].ToString() + plainText[i].ToString() + plainText[2 * i].ToString();
                if (cipherText.Contains(S1)){
                    //second column index 1,4,7 
                    string S2 = plainText[1].ToString() + plainText[i + 1].ToString() + plainText[(i * 2) + 1].ToString();
                    if (cipherText.Contains(S2)){
                        //get the length of the key
                        L = i;
                        break;
                    }
                }
            }
            // Rows number
            int Rows = P_TLength / L;
            // here, we need to know the location of each column in both cipher and plain
            // J loops about columns
            for (int j = 0; j < L; j++)
            {
                // so we check each columns where its located in the plain text
                // we also check the columns place in cipher
                string s3 = plainText[j].ToString() + plainText[j + L].ToString() + plainText[j + (2 * L)].ToString();
                int column_index = (cipherText.IndexOf(s3) / Rows) + 1;
                key.Add(column_index);
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        { //throw new NotImplementedException();
            try
            {
                //init dect
                Dictionary <int, int> Dect1 = new Dictionary <int, int> ();
                //init values
                string P_T = "";
                int KeyMax = key.Max();
                //calculate the num of columns (apply celiling)
                int Rows = (cipherText.Length + KeyMax - 1) / KeyMax;
                //loop on KeyMax 
                for (int i = 0; i < KeyMax; i++){
                //append (key,value = i,key[i]-1)(zero based) in Dect1
                    Dect1.Add(i, key[i] - 1);
                }
                //nit var First = the value of Dect1[0]
                int First = Dect1[0];
                //loop on the rows
                for (int j = 0; j < Rows; j++){
                    //loop on the KeyMax
                    for (int x = 0; x < KeyMax; x++){
                        int y = (First * Rows) + j;
                        //add value y to the P.T 
                        P_T += cipherText[y];
                        //reassign the value of First
                        First = x + 1;
                        First = First % KeyMax;
                        //First = the value of Decti[First]
                        First = Dect1[First];
                    }

                }
                //return P.T
                return P_T;
            }
            catch (System.Exception){
                return cipherText;
            }
}

        public string Encrypt(string plainText, List<int> key)
        {
            // throw new NotImplementedException();

            //init var
            string C_T = "";
            int index = 0;
            int KeyMax = key.Max();

            //init dict
            Dictionary<int, int> Dict1 = new Dictionary<int, int>();

            //calculate the num of rows (apply celiling)
            int Rows = (plainText.Length + KeyMax - 1) / KeyMax;

            //map  the indices of the key( 13425 -> 02314 )to zero based indices
            for (int i = 0; i < KeyMax; i++){
                index = key.FindIndex(x => x == i+1);
                //add in dict1 {(0,0),(1,3),...}
                Dict1.Add(i, index);
            }
            //loop in the dict1 
            foreach (var Columns in Dict1){
                int col_value = Columns.Value;
                //loop in the rows
                for (int j = 0; j < Rows; j++){
                    //check if the P.T over the length
                    if (col_value >= plainText.Length) break;
                    //add the chars in C.T
                    C_T += plainText[col_value];
                    //increase col_value by the max num in the key
                    col_value += KeyMax;
                }
            }
            //finally return the C.T
            return C_T;
        }
    }
}
