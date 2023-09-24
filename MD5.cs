using System;
using System.Collections.Generic;
using System.Text;
using SecurityLibrary.AES;

namespace SecurityLibrary.MD5
{
    public class MD5
    {
        public string GetHash(string text)
        {
            //throw new NotImplementedException();
            MatrixOP m = new MatrixOP();
            return m.tohexString(m.ComputeMD5(Encoding.ASCII.GetBytes(text)));
        }
        public class MatrixOP
        {
            public MatrixOP() { }
            public uint A = 0x67452301;
            public uint B = 0xEFCDAB89;
            public uint C = 0x98BADCFE;
            public uint D = 0x10325476;
            public int[] shifts = new int[] { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };
            public static long TripleShift(long n, int s)
            {
                if (n >= 0)
                    return n >> s;
                return (n >> s) + (2 << ~s);
            }
            public uint rotateLeft(uint x, int n)
            {
                return (x << n) | (x >> (32 - n));
            }
            public byte[] ComputeMD5(byte[] message)
            {
                uint[] table = new uint[64];
                for (int i = 0; i < 64; i++)
                    table[i] = (uint)(long)((1L << 32) * Math.Abs(Math.Sin(i + 1)));

                int messLenBytes = message.Length;

                int numblocks = ((int)(TripleShift((messLenBytes + 8), 6))) + 1; //(messLenBytes + 8) >> 6

                int totalLen = numblocks << 6;

                byte[] paddingBytes = new byte[totalLen - messLenBytes];

                paddingBytes[0] = (byte)0x80;

                long messageLenBits = (long)messLenBytes << 3;

                for (int i = 0; i < 8; i++)
                {
                    paddingBytes[paddingBytes.Length - 8 + i] = (byte)messageLenBits;
                    messageLenBits = (long)TripleShift(messageLenBits, 8);
                }
                uint a = A;
                uint b = B;
                uint c = C;
                uint d = D;
                int[] buffer = new int[16];
                for (int i = 0; i < numblocks; i++)
                {
                    int index = i << 6;
                    for (int j = 0; j < 64; j++, index++)
                    {
                        buffer[TripleShift(j, 2)] = ((int)((index < messLenBytes) ? message[index] : paddingBytes[index - messLenBytes]) << 24) | ((int)TripleShift(buffer[TripleShift(j, 2)], 8));//buffer[TripleShift(j,2)] >>> 8
                    }
                    uint originalA = a;
                    uint originalB = b;
                    uint originalC = c;
                    uint originalD = d;
                    for (int j = 0; j < 64; j++)
                    {
                        int div16 = (int)TripleShift(j, 4);
                        int f = 0;
                        int bufferindex = j;
                        switch (div16)
                        {
                            case 0:
                                f = (int)((b & c) | (~b & d));
                                break;
                            case 1:
                                f = (int)((b & d) | (c & ~d));
                                bufferindex = (bufferindex * 5 + 1) & 0x0F;
                                break;
                            case 2:
                                f = (int)(b ^ c ^ d);
                                bufferindex = (bufferindex * 3 + 5) & 0x0F;
                                break;
                            case 3:
                                f = (int)(c ^ (b | ~d));
                                bufferindex = (bufferindex * 7) & 0x0F;
                                break;

                        }
                        uint temp = (uint)(b + rotateLeft((uint)(a + f + buffer[bufferindex] + table[j]), shifts[(div16 << 2) | (j & 3)]));
                        a = d;
                        d = c;
                        c = b;
                        b = temp;
                    }
                    a += originalA;
                    b += originalB;
                    c += originalC;
                    d += originalD;
                }
                byte[] md5 = new byte[16];
                int count = 0;
                for (int i = 0; i < 4; i++)
                {
                    int n = (i == 0) ? (int)a : ((i == 1) ? (int)b : ((i == 2) ? (int)c : (int)d));
                    for (int j = 0; j < 4; j++)
                    {
                        md5[count++] = (byte)n;
                        n = (int)TripleShift(n, 8);
                    }
                }
                return md5;
            }
            public string tohexString(byte[] b)
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < b.Length; i++)
                {
                    sb.Append(string.Format("{0:X2}", (b[i] & 0xFF)));
                }
                return sb.ToString();
            }
            public int SignOfElement(int i, int j)
            {
                if ((i + j) % 2 == 0)
                {
                    return 1;
                }
                else
                {
                    return -1;
                }
            }
            //this method determines the sub matrix corresponding to a given element
            public double[,] CreateSmallerMatrix(double[,] input, int i, int j)
            {
                int order = int.Parse(System.Math.Sqrt(input.Length).ToString());
                double[,] output = new double[order - 1, order - 1];
                int x = 0, y = 0;
                for (int m = 0; m < order; m++, x++)
                {
                    if (m != i)
                    {
                        y = 0;
                        for (int n = 0; n < order; n++)
                        {
                            if (n != j)
                            {
                                output[x, y] = input[m, n];
                                y++;
                            }
                        }
                    }
                    else
                    {
                        x--;
                    }
                }
                return output;
            }
            public Byte GMul(Byte a, Byte b)
            { // Galois Field (256) Multiplication of two Bytes
                Byte p = 0;
                Byte counter;
                Byte hi_bit_set;
                for (counter = 0; counter < 8; counter++)
                {
                    if ((b & 1) != 0)
                    {
                        p ^= a;
                    }
                    hi_bit_set = (Byte)(a & 0x80);
                    a <<= 1;
                    if (hi_bit_set != 0)
                    {
                        a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
                    }
                    b >>= 1;
                }
                return p;
            }

            public byte[,] MixColumns(byte[,] s)
            { // 's' is the main State matrix, 'ss' is a temp matrix of the same dimensions as 's'.
                Byte[,] ss = new Byte[4, 4];
                for (int c = 0; c < 4; c++)
                {
                    ss[0, c] = (Byte)(GMul(0x02, s[0, c]) ^ GMul(0x03, s[1, c]) ^ s[2, c] ^ s[3, c]);
                    ss[1, c] = (Byte)(s[0, c] ^ GMul(0x02, s[1, c]) ^ GMul(0x03, s[2, c]) ^ s[3, c]);
                    ss[2, c] = (Byte)(s[0, c] ^ s[1, c] ^ GMul(0x02, s[2, c]) ^ GMul(0x03, s[3, c]));
                    ss[3, c] = (Byte)(GMul(0x03, s[0, c]) ^ s[1, c] ^ s[2, c] ^ GMul(0x02, s[3, c]));
                }

                //ss.CopyTo(s, 0);
                return ss;
            }
            public string XOR(string p, string k)
            {
                string se = "";
                for (int i = 0; i < p.Length; i++)
                {
                    if (p[i] == '0' && k[i] == '0')
                    {
                        se += "0";
                    }
                    else if (p[i] == '0' && k[i] == '1')
                    {
                        se += "1";
                    }
                    else if (p[i] == '1' && k[i] == '0')
                    {
                        se += "1";
                    }
                    else
                    {
                        se += "0";
                    }
                }
                return se;
            }
            public int calculateInverse(string s)
            {
                ExtendedEuclid e = new ExtendedEuclid();
                Dictionary<char, int> DT = new Dictionary<char, int>();
                Dictionary<int, char> CT = new Dictionary<int, char>();
                int cnt = 0;
                for (char c = 'a'; c <= 'z'; c++)
                {
                    DT[c] = cnt;
                    CT[cnt] = c;
                    cnt++;
                }
                int A = DT[s[0]];
                int B = DT[s[1]]; ;
                int C = DT[s[2]]; ;
                int D = DT[s[3]]; ;
                int determinant = (A * D) - (C * B);
                int inverseMultiplicative = e.GetMultiplicativeInverse(determinant, 26);
                return inverseMultiplicative;
            }
            public int Inversekey(string s)
            {
                ExtendedEuclid e = new ExtendedEuclid();
                Dictionary<char, int> DT = new Dictionary<char, int>();
                Dictionary<int, char> CT = new Dictionary<int, char>();
                int cnt = 0;
                for (char c = 'a'; c <= 'z'; c++)
                {
                    DT[c] = cnt;
                    CT[cnt] = c;
                    cnt++;
                }
                double[,] keymat = new double[3, 3];
                int rp = 0;
                for (int i = 0; i < 3; i++)
                {
                    int cc = rp;
                    for (int j = 0; j < 3; j++)
                    {
                        keymat[i, j] = DT[s[cc]];
                        rp++;
                        cc++;
                    }
                    cc = rp;
                }
                int determinant = int.Parse(Matrix.Determinant(keymat).ToString());
                while (determinant > 26) determinant -= 26;
                while (determinant < 0) determinant += 26;
                int inverseMultiplicative = e.GetMultiplicativeInverse(determinant, 26);
                return inverseMultiplicative;
            }
        }

    }
}
