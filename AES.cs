using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        public string Make_New_Key(string Key, string Rcon)
        {
            string Key_New = "0x";
            string Col = "";
            string Shifted_Colm = "";

            Shifted_Colm = Key.Substring(28, 6);
            Shifted_Colm = Shifted_Colm + Key.Substring(26, 2);
            Key = Key.Substring(2);
            Col = Col + SubBytes_Decrybt("0x" + Shifted_Colm);
            Col = Col.Substring(2);
            for (int i = 0; i <= 3; i++)
            {
                string S1 = "";
                for (int j = 0; j <= 3; j++)
                {
                    byte Col_Last = Convert.ToByte(Col.Substring(j * 2, 2), 16);
                    byte Col1 = Convert.ToByte(Key.Substring((i * 8) + (j * 2), 2), 16);
                    //XOR Operator
                    byte Result = (byte)(Col1 ^ Col_Last);
                    if (i == 0)
                    {
                        byte RconB = Convert.ToByte(Rcon.Substring(j * 2, 2), 16);
                        Result = (byte)(Result ^ RconB);
                    }
                    if (Result.ToString("x").Length == 1) S1 = S1 + '0';
                    S1 = S1 + Result.ToString("x");
                }
                Key_New = Key_New + S1;
                Col = S1;
            }
            return Key_New;
        }

        public string SubBytes_Decrybt(string Plain_Text)
        {
            int P_T_L = Plain_Text.Length;
            string P_T = "0x";
            string[,] SBox = new string[16, 16] {
              {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
              {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
              {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
              {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
              {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
              {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
              {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
              {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
              {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
              {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
              {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
              {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
              {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
              {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
              {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
              {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
            };
            for (int i = 2; i < P_T_L; i = i + 2)
            {
                int A = int.Parse("0" + Plain_Text[i], System.Globalization.NumberStyles.HexNumber);
                int B = int.Parse("0" + Plain_Text[i + 1], System.Globalization.NumberStyles.HexNumber);
                string New_SBox = SBox[A, B];
                P_T = P_T + New_SBox;
            }
            return P_T;
        }

        public string Add_Round_Key(string Plain_Text, string Key)
        {
            string Num_Hexa = "";
            for (int i = 0; i <= 3; i++)
            {
                long Num1 = Convert.ToInt64(Key.Substring(i * 8, 8), 16);
                long Num2 = Convert.ToInt64(Plain_Text.Substring(i * 8, 8), 16);
                //XOR Operator
                long Result = Num1 ^ Num2;
                int Res_Length = Result.ToString("x").Length;
                while (Res_Length != 8)
                {
                    Num_Hexa = Num_Hexa + '0';
                    Res_Length = Res_Length + 1;
                }
                Num_Hexa += Result.ToString("X");
            }
            Num_Hexa = "0x" + Num_Hexa;
            return Num_Hexa;
        }

        public string Inv_Shift_Col(string Plain_Text)
        {
            string[] Col1 = new string[4];
            int[][] arr = { new int[] { 14, 11, 13, 9 }, new int[] { 9, 14, 11, 13 },
                            new int[] { 13, 9, 14, 11 }, new int[] { 11, 13, 9, 14 }};
            for (int i = 0; i <= 3; i++)
            {
                string S1 = "";
                S1 = S1 + Plain_Text.Substring(i * 8, 8);
                Col1[i] = S1;
            }
            string Col_New = "";
            for (int X = 0; X <= 3; X++)
            {
                for (int i = 0; i <= 3; i++)
                {
                    byte Result = 0;
                    for (int j = 0; j <= 3; j++)
                    {
                        string Text = Col1[X].Substring(j * 2, 2);
                        byte Num = 0;
                        byte Text_To_Hexa = Convert.ToByte(Text, 16);
                        if (arr[i][j] == 14)
                        {
                            Num = Shifted_Last_Bit(Text);
                            Num = (byte)(Num ^ Text_To_Hexa);
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = (byte)(Num ^ Text_To_Hexa);
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                        }
                        else if (arr[i][j] == 11)
                        {
                            Num = Shifted_Last_Bit(Text);
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = (byte)(Num ^ Text_To_Hexa);
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = (byte)(Num ^ Text_To_Hexa);
                        }
                        else if (arr[i][j] == 13)
                        {
                            Num = Shifted_Last_Bit(Text);
                            Num = (byte)(Num ^ Text_To_Hexa);
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = (byte)(Num ^ Text_To_Hexa);
                        }
                        else if (arr[i][j] == 9)
                        {
                            Num = Shifted_Last_Bit(Text);
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = Shifted_Last_Bit(Num.ToString("x"));
                            Num = (byte)(Num ^ Text_To_Hexa);
                        }
                        Result = (byte)(Result ^ Num);
                    }
                    if (Result.ToString("x").Length == 1)
                    {
                        Col_New = Col_New + '0' + Result.ToString("x");
                    }
                    else
                        Col_New = Col_New + Result.ToString("x");
                }
            }
            string Final_Res = "0x" + Col_New;
            return Final_Res;
        }

        public byte Shifted_Last_Bit(string Text)
        {
            bool Flag_XOR = false;
            if (Text.Length == 1)
                Text = "0" + Text;
            byte Num = Convert.ToByte(Text, 16);
            // Convert Hexa to binary
            string Binary = String.Join(String.Empty, Text.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
            string Num_H_To_B = Binary;
            byte Num_Bytes = Convert.ToByte(Text, 16);
            if (Num_H_To_B[0] == '1')
                Flag_XOR = true;
            Num_Bytes <<= 1;
            if (Flag_XOR == true)
                Num_Bytes = (byte)(Num_Bytes ^ Convert.ToByte("0x1b", 16));
            return Num_Bytes;
        }

        public string Inverse_shiftrows(string plainText)
        {
            string new_string = "";
            string new_string1 = "";
            int begining = 8;
            string end = "0x";

            for (int i = 0; i < 4; i++)
            {
                //divide the matrix into cols
                for (int j = 0; j < 4; j++)
                {
                    new_string += plainText.Substring((j * 8) + (i * 2), 2);

                }

            }

            new_string1 += new_string.Substring(0, 8);

            for (int i = 3; i > 0; i--)
            {
                string str = new_string.Substring(begining, 8);
                new_string1 += str.Substring(i * 2, 8 - (i * 2));
                new_string1 += str.Substring(0, i * 2);
                begining += 8;
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    end += new_string1.Substring((j * 8) + (i * 2), 2);

                }
            }
            return end;
        }

        public string Inv_Sub_Bytes(string Plain_Text)
        {
            int Len = Plain_Text.Length;
            string P_T_New = "0x";
            string[,] Inv_SBox = new string[16, 16]
            {
             {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
             {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
             {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
             {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
             {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
             {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
             {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
             {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
             {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
             {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
             {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
             {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
             {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
             {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
             {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
             {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}};
            for (int i = 2; i < Len; i = i + 2)
            {
                int A = int.Parse("0" + Plain_Text[i], System.Globalization.NumberStyles.HexNumber);
                int B = int.Parse("0" + Plain_Text[i + 1], System.Globalization.NumberStyles.HexNumber);
                P_T_New = P_T_New + Inv_SBox[A, B];
            }
            return P_T_New;
        }

        public override string Decrypt(string cipherText, string key)
        {
            string[] Rcon = { "01000000" , "02000000", "04000000", "08000000", "10000000",
                              "20000000", "40000000", "80000000", "1b000000", "36000000" };
            string[] keys = new string[11];
            keys[0] = key;
            int Len_Key = keys.Length;
            for (int i = 1; i < Len_Key; i++)
            {
                keys[i] = Make_New_Key(keys[i - 1], Rcon[i - 1]);

            }
            for (int i = Len_Key - 1; i > 0; i--)
            {
                cipherText = Add_Round_Key(cipherText.Substring(2), keys[i].Substring(2));
                if (i != 10)
                    cipherText = Inv_Shift_Col(cipherText.Substring(2));
                cipherText = Inverse_shiftrows(cipherText.Substring(2));
                cipherText = Inv_Sub_Bytes(cipherText);
            }
            cipherText = Add_Round_Key(cipherText.Substring(2), keys[0].Substring(2));
            return cipherText;
        }

        public string xor(string s1, string s2)
        {
            // xor in binary
            string resultXORbin = "";
            for (int k = 0; k < s1.Length; k++)
            {
                if (s1[k] == s2[k])
                {
                    resultXORbin += "0";
                }
                else
                {
                    resultXORbin += "1";
                }
            }
            return resultXORbin;
        }

        public string binaryToHexa(string s1)
        {
            Dictionary<string, char> result = new Dictionary<string, char>();
            result.Add("0000", '0');
            result.Add("0001", '1');
            result.Add("0010", '2');
            result.Add("0011", '3');
            result.Add("0100", '4');
            result.Add("0101", '5');
            result.Add("0110", '6');
            result.Add("0111", '7');
            result.Add("1000", '8');
            result.Add("1001", '9');
            result.Add("1010", 'A');
            result.Add("1011", 'B');
            result.Add("1100", 'C');
            result.Add("1101", 'D');
            result.Add("1110", 'E');
            result.Add("1111", 'F');

            // conert xorBinary to hexi
            string sub1 = s1.Substring(0, 4);
            string sub2 = s1.Substring(4, 4);

            string hexa = result[sub1] + "" + result[sub2];

            return hexa;
        }

        public string xorResult(string subPlain, string subKey)
        {
            // Convert hexadecimal to 4 bit binary
            string subPlainBin = string.Join("", subPlain.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
            string subKeyBin = string.Join("", subKey.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));

            // xor in binary
            string resultXORbin = xor(subPlainBin, subKeyBin);

            string finalResult = binaryToHexa(resultXORbin).ToString();
            return finalResult;
        }

        public string SubBytes(string sub)
        {
            sub = sub.ToLower();
            Dictionary<char, string> numbers = new Dictionary<char, string>();
            numbers.Add('a', "10");
            numbers.Add('b', "11");
            numbers.Add('c', "12");
            numbers.Add('d', "13");
            numbers.Add('e', "14");
            numbers.Add('f', "15");
            string[,] S_Box = new string[16, 16]
            {
                {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
                {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
                {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
                {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
                {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
                {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
                {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
                {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
                {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
                {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
                {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
                {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
                {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
                {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
                {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
                {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };

            string s1 = sub.Substring(0, 1), s2 = sub.Substring(1, 1);
            if (numbers.ContainsKey(sub[0]))
                s1 = numbers[sub[0]];
            if (numbers.ContainsKey(sub[1]))
                s2 = numbers[sub[1]];

            string result = S_Box[Int32.Parse(s1), Int32.Parse(s2)];

            return result;
        }

        public string[,] shiftRows(string[,] matrix)
        {
            // for second raw
            string s = matrix[1, 0];
            matrix[1, 0] = matrix[1, 1];
            matrix[1, 1] = matrix[1, 2];
            matrix[1, 2] = matrix[1, 3];
            matrix[1, 3] = s;

            // for third raw
            string s1 = matrix[2, 0];
            s = matrix[2, 1];
            matrix[2, 0] = matrix[2, 2];
            matrix[2, 1] = matrix[2, 3];
            matrix[2, 2] = s1;
            matrix[2, 3] = s;

            // forth raw
            string s2 = matrix[3, 0];
            s1 = matrix[3, 1];
            s = matrix[3, 2];
            matrix[3, 0] = matrix[3, 3];
            matrix[3, 1] = s2;
            matrix[3, 2] = s1;
            matrix[3, 3] = s;

            // convert matrix array to binary
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Convert hexadecimal to 4 bit binary
                    matrix[i, j] = string.Join("", matrix[i, j].Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
                }
            }

            return matrix;
        }


        public string mix_two(string s)
        {
            // matrix[j, i][0]
            if (s[0] == '0')
            {
                // if last bit == 0
                s = s.Remove(0, 1);
                s = s + '0';
            }
            else
            {
                // last bit == 1 (matrix[j, i] XOR 1B)
                string B = "00011011";
                s = s.Remove(0, 1);
                s = s + '0';
                // xor in binary
                string resultXORbin = xor(s, B);
                //replace result in matrix
                s = resultXORbin;
            }
            // s= d4 * 02
            return s;
        }

        public string[,] mix_Column(string[,] matrix)
        {
            string[,] mix_ColumnResult = new string[4, 4];

            string[,] GF = new string[4, 4]
            {
                { "2" , "3" , "1" , "1"},
                { "1" , "2" , "3" , "1"},
                { "1" , "1" , "2" , "3"},
                { "3" , "1" , "1" , "2"}
            };

            // multiply 
            for (int k = 0; k < 4; k++)  // k=0
            {
                for (int i = 0; i < 4; i++) //i=0
                {
                    string resultVector = "00000000";
                    for (int j = 0; j < 4; j++) //j=0
                    {
                        string temp = "";
                        if (GF[i, j] == "1")
                        {
                            temp = matrix[j, k];
                        }
                        else if (GF[i, j] == "2")
                        {
                            temp = mix_two(matrix[j, k]);
                        }
                        else if (GF[i, j] == "3")
                        {
                            string x1 = matrix[j, k];
                            string y1 = mix_two(matrix[j, k]);
                            // xor in binary
                            string resultXORbin = xor(x1, y1);
                            temp = resultXORbin;
                        }
                        // addition
                        resultVector = xor(resultVector, temp); // d4 + 

                    }

                    //mix_ColumnResult[i, k] = binaryToHexa(resultVector);
                    mix_ColumnResult[i, k] = resultVector;
                }
            }


            return mix_ColumnResult;
        }



        public string[,] CreateRoundKey(string[,] keyMatrix, int roundNumber)
        {
            string[,] Rcon = new string[4, 10] {
                { "00000001", "00000010", "00000100", "00001000", "00010000", "00100000", "01000000", "10000000", "00011011", "00110110" },
                { "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000" },
                { "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000" },
                { "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000" }
            };

            string[,] newMatrix = new string[4, 4];
            // swap last column
            string temp = keyMatrix[0, 3];
            newMatrix[0, 0] = keyMatrix[1, 3];
            newMatrix[1, 0] = keyMatrix[2, 3];
            newMatrix[2, 0] = keyMatrix[3, 3];
            newMatrix[3, 0] = temp;

            // apply subbytes
            for (int i = 0; i < 4; i++)
            {
                newMatrix[i, 0] = SubBytes(newMatrix[i, 0]);
            }

            // XOR keyMatrix with newMatrix

            // convert KeyMatrix array to binary
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Convert hexadecimal to 4 bit binary
                    keyMatrix[i, j] = string.Join("", keyMatrix[i, j].Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
                }
            }

            // convert last column in newMatrix to binary 
            for (int i = 0; i < 4; i++)
            {
                newMatrix[i, 0] = string.Join("", newMatrix[i, 0].Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
            }

            // first column in key round
            for (int j = 0; j < 4; j++)
            {
                newMatrix[j, 0] = xor(keyMatrix[j, 0], newMatrix[j, 0]);
                newMatrix[j, 0] = xor(newMatrix[j, 0], Rcon[j, roundNumber]);
            }

            // other columns in key round
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    newMatrix[j, i] = xor(keyMatrix[j, i], newMatrix[j, i - 1]);
                }
            }

            /*
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // first column in key round
                    newMatrix[j, i] = binaryToHexa(newMatrix[j, i]);
                }
            }
            */

            return newMatrix;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string ciphertext = "0x";

            // convert key to matrix
            string XORResult = "";
            for (int i = 2; i < plainText.Length; i += 2)
            {
                string sub_plain = plainText.Substring(i, 2);
                string sub_key = key.Substring(i, 2);

                XORResult = XORResult + xorResult(sub_plain, sub_key);
            }

            // convert XORResult to 2d matrix
            string[,] finalPlain = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            int z = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    finalPlain[j, i] = XORResult.Substring(z, 2);
                    keyMatrix[j, i] = key.Substring(z + 2, 2);
                    z += 2;
                }
            }

            for (int q = 0; q < 10; q++)
            {
                // 1 - sub matrix
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        finalPlain[i, j] = SubBytes(finalPlain[i, j]);
                    }
                }

                // 2 - Shift Rows
                finalPlain = shiftRows(finalPlain);

                if (q != 9)
                {
                    // 3 - mix column
                    finalPlain = mix_Column(finalPlain);
                }

                // 4 -  AddRoundKey

                string[,] RoundKey = CreateRoundKey(keyMatrix, q);
                string[,] Temp = RoundKey;
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        finalPlain[j, i] = xor(finalPlain[j, i], Temp[j, i]);
                        // convert to hexa
                        finalPlain[j, i] = binaryToHexa(finalPlain[j, i]);

                        RoundKey[j, i] = binaryToHexa(RoundKey[j, i]);
                    }
                }

                keyMatrix = RoundKey;

            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ciphertext += finalPlain[j, i];
                }
            }

            return ciphertext;
        }

    }

}