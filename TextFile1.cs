using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
string C_T = "";
//init values
public string Encrypt(string plainText, List<int> key)
{
    // throw new NotImplementedException();
    //init var
    string C_T = "";
    //init values
    int count = 0;
    //init dict
    Dictionary<int, int> Dict1 = new Dictionary<int, int>();
    //calculate the num of rows (apply celiling)
    int rows = (plainText.Length + key.Count - 1) / key.Count;
    for (int i = 0; i < key.Max(); i++)
    {
        int index = key.FindIndex(x => x == i + 1);
        Dict1.Add(i, index);
    }
    foreach (var col in Dict1)
    {
        int n = col.Value;
        for (int j = 0; j < rows; j++)
        {
            if (n >= plainText.Length)
            {
                break;
            }
            C_T += plainText[n];
            n += key.Max();
        }
        count++;
    }
    return C_T;
}
