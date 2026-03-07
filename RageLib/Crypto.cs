using v1mertool.Helper;

namespace v1mertool.Crypto
{
    public interface IEncryptionAlgorithm
    {
        byte[] Decrypt(byte[] data);
    }

    public static class GTA5Constants
    {
        public static void LoadFromPath(string path)
        {
            GTA5Constants.PC_NG_KEYS = CryptoIO.ReadNgKeys(path + "\\gtav_ng_key.dat");
            GTA5Constants.PC_NG_DECRYPT_TABLES = CryptoIO.ReadNgTables(path + "\\gtav_ng_decrypt_tables.dat");
            GTA5Constants.PC_NG_ENCRYPT_TABLES = CryptoIO.ReadNgTables(path + "\\gtav_ng_encrypt_tables.dat");
            GTA5Constants.PC_NG_ENCRYPT_LUTs = CryptoIO.ReadNgLuts(path + "\\gtav_ng_encrypt_luts.dat");
            GTA5Constants.PC_LUT = File.ReadAllBytes(path + "\\gtav_hash_lut.dat");
        }

        public static byte[][] PC_NG_KEYS;

        public static uint[][][] PC_NG_DECRYPT_TABLES;

        public static uint[][][] PC_NG_ENCRYPT_TABLES;

        public static byte[] PC_LUT;

        public static GTA5NGLUT[][] PC_NG_ENCRYPT_LUTs;

    }

    

    public class GTA5Crypto : IEncryptionAlgorithm
    {
        public byte[] Key { get; set; }

        public byte[] Decrypt(byte[] data)
        {
            return GTA5Crypto.Decrypt(data, this.Key);
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            byte[] array = new byte[data.Length];
            uint[] array2 = new uint[key.Length / 4];
            Buffer.BlockCopy(key, 0, array2, 0, key.Length);
            for (int i = 0; i < data.Length / 16; i++)
            {
                byte[] array3 = new byte[16];
                Array.Copy(data, 16 * i, array3, 0, 16);
                Array.Copy(GTA5Crypto.DecryptBlock(array3, array2), 0, array, 16 * i, 16);
            }
            if (data.Length % 16 != 0)
            {
                int num = data.Length % 16;
                Buffer.BlockCopy(data, data.Length - num, array, data.Length - num, num);
            }
            return array;
        }

        public static byte[] DecryptBlock(byte[] data, uint[] key)
        {
            uint[][] array = new uint[17][];
            for (int i = 0; i < 17; i++)
            {
                array[i] = new uint[4];
                array[i][0] = key[4 * i];
                array[i][1] = key[4 * i + 1];
                array[i][2] = key[4 * i + 2];
                array[i][3] = key[4 * i + 3];
            }
            byte[] data2 = GTA5Crypto.DecryptRoundA(data, array[0], GTA5Constants.PC_NG_DECRYPT_TABLES[0]);
            data2 = GTA5Crypto.DecryptRoundA(data2, array[1], GTA5Constants.PC_NG_DECRYPT_TABLES[1]);
            for (int j = 2; j <= 15; j++)
            {
                data2 = GTA5Crypto.DecryptRoundB(data2, array[j], GTA5Constants.PC_NG_DECRYPT_TABLES[j]);
            }
            return GTA5Crypto.DecryptRoundA(data2, array[16], GTA5Constants.PC_NG_DECRYPT_TABLES[16]);
        }

        public static byte[] DecryptRoundA(byte[] data, uint[] key, uint[][] table)
        {
            uint value = table[0][(int)data[0]] ^ table[1][(int)data[1]] ^ table[2][(int)data[2]] ^ table[3][(int)data[3]] ^ key[0];
            uint value2 = table[4][(int)data[4]] ^ table[5][(int)data[5]] ^ table[6][(int)data[6]] ^ table[7][(int)data[7]] ^ key[1];
            uint value3 = table[8][(int)data[8]] ^ table[9][(int)data[9]] ^ table[10][(int)data[10]] ^ table[11][(int)data[11]] ^ key[2];
            uint value4 = table[12][(int)data[12]] ^ table[13][(int)data[13]] ^ table[14][(int)data[14]] ^ table[15][(int)data[15]] ^ key[3];
            byte[] array = new byte[16];
            Array.Copy(BitConverter.GetBytes(value), 0, array, 0, 4);
            Array.Copy(BitConverter.GetBytes(value2), 0, array, 4, 4);
            Array.Copy(BitConverter.GetBytes(value3), 0, array, 8, 4);
            Array.Copy(BitConverter.GetBytes(value4), 0, array, 12, 4);
            return array;
        }

        public static byte[] DecryptRoundB(byte[] data, uint[] key, uint[][] table)
        {
            uint num = table[0][(int)data[0]] ^ table[7][(int)data[7]] ^ table[10][(int)data[10]] ^ table[13][(int)data[13]] ^ key[0];
            uint num2 = table[1][(int)data[1]] ^ table[4][(int)data[4]] ^ table[11][(int)data[11]] ^ table[14][(int)data[14]] ^ key[1];
            uint num3 = table[2][(int)data[2]] ^ table[5][(int)data[5]] ^ table[8][(int)data[8]] ^ table[15][(int)data[15]] ^ key[2];
            uint num4 = table[3][(int)data[3]] ^ table[6][(int)data[6]] ^ table[9][(int)data[9]] ^ table[12][(int)data[12]] ^ key[3];
            return new byte[]
            {
                (byte)(num & 255U),
                (byte)(num >> 8 & 255U),
                (byte)(num >> 16 & 255U),
                (byte)(num >> 24 & 255U),
                (byte)(num2 & 255U),
                (byte)(num2 >> 8 & 255U),
                (byte)(num2 >> 16 & 255U),
                (byte)(num2 >> 24 & 255U),
                (byte)(num3 & 255U),
                (byte)(num3 >> 8 & 255U),
                (byte)(num3 >> 16 & 255U),
                (byte)(num3 >> 24 & 255U),
                (byte)(num4 & 255U),
                (byte)(num4 >> 8 & 255U),
                (byte)(num4 >> 16 & 255U),
                (byte)(num4 >> 24 & 255U)
            };
        }

        public byte[] Encrypt(byte[] data)
        {
            return GTA5Crypto.Encrypt(data, this.Key);
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            byte[] array = new byte[data.Length];
            uint[] array2 = new uint[key.Length / 4];
            Buffer.BlockCopy(key, 0, array2, 0, key.Length);
            for (int i = 0; i < data.Length / 16; i++)
            {
                byte[] array3 = new byte[16];
                Array.Copy(data, 16 * i, array3, 0, 16);
                Array.Copy(GTA5Crypto.EncryptBlock(array3, array2), 0, array, 16 * i, 16);
            }
            if (data.Length % 16 != 0)
            {
                int num = data.Length % 16;
                Buffer.BlockCopy(data, data.Length - num, array, data.Length - num, num);
            }
            return array;
        }

        public static byte[] EncryptBlock(byte[] data, uint[] key)
        {
            uint[][] array = new uint[17][];
            for (int i = 0; i < 17; i++)
            {
                array[i] = new uint[4];
                array[i][0] = key[4 * i];
                array[i][1] = key[4 * i + 1];
                array[i][2] = key[4 * i + 2];
                array[i][3] = key[4 * i + 3];
            }
            byte[] array2 = GTA5Crypto.EncryptRoundA(data, array[16], GTA5Constants.PC_NG_ENCRYPT_TABLES[16]);
            for (int j = 15; j >= 2; j--)
            {
                array2 = GTA5Crypto.EncryptRoundB_LUT(array2, array[j], GTA5Constants.PC_NG_ENCRYPT_LUTs[j]);
            }
            array2 = GTA5Crypto.EncryptRoundA(array2, array[1], GTA5Constants.PC_NG_ENCRYPT_TABLES[1]);
            return GTA5Crypto.EncryptRoundA(array2, array[0], GTA5Constants.PC_NG_ENCRYPT_TABLES[0]);
        }

        public static byte[] EncryptRoundA(byte[] data, uint[] key, uint[][] table)
        {
            byte[] array = new byte[16];
            Buffer.BlockCopy(key, 0, array, 0, 16);
            uint value = table[0][(int)(data[0] ^ array[0])] ^ table[1][(int)(data[1] ^ array[1])] ^ table[2][(int)(data[2] ^ array[2])] ^ table[3][(int)(data[3] ^ array[3])];
            uint value2 = table[4][(int)(data[4] ^ array[4])] ^ table[5][(int)(data[5] ^ array[5])] ^ table[6][(int)(data[6] ^ array[6])] ^ table[7][(int)(data[7] ^ array[7])];
            uint value3 = table[8][(int)(data[8] ^ array[8])] ^ table[9][(int)(data[9] ^ array[9])] ^ table[10][(int)(data[10] ^ array[10])] ^ table[11][(int)(data[11] ^ array[11])];
            uint value4 = table[12][(int)(data[12] ^ array[12])] ^ table[13][(int)(data[13] ^ array[13])] ^ table[14][(int)(data[14] ^ array[14])] ^ table[15][(int)(data[15] ^ array[15])];
            byte[] array2 = new byte[16];
            Array.Copy(BitConverter.GetBytes(value), 0, array2, 0, 4);
            Array.Copy(BitConverter.GetBytes(value2), 0, array2, 4, 4);
            Array.Copy(BitConverter.GetBytes(value3), 0, array2, 8, 4);
            Array.Copy(BitConverter.GetBytes(value4), 0, array2, 12, 4);
            return array2;
        }

        public static byte[] EncryptRoundA_LUT(byte[] dataOld, uint[] key, GTA5NGLUT[] lut)
        {
            byte[] array = (byte[])dataOld.Clone();
            byte[] array2 = new byte[16];
            Buffer.BlockCopy(key, 0, array2, 0, 16);
            for (int i = 0; i < 16; i++)
            {
                byte[] array3 = array;
                int num = i;
                int num2 = num;
                array3[num2] ^= array2[i];
            }
            return new byte[]
            {
                lut[0].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[1].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[2].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[3].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[4].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[5].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[6].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[7].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[8].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[9].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[10].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[11].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[12].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[13].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[14].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[15].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0))
            };
        }

        public static byte[] EncryptRoundB_LUT(byte[] dataOld, uint[] key, GTA5NGLUT[] lut)
        {
            byte[] array = (byte[])dataOld.Clone();
            byte[] array2 = new byte[16];
            Buffer.BlockCopy(key, 0, array2, 0, 16);
            for (int i = 0; i < 16; i++)
            {
                byte[] array3 = array;
                int num = i;
                int num2 = num;
                array3[num2] ^= array2[i];
            }
            return new byte[]
            {
                lut[0].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[1].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[2].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[3].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[4].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[5].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[6].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[7].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[8].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0)),
                lut[9].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[10].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[11].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[12].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[12],
                    array[13],
                    array[14],
                    array[15]
                }, 0)),
                lut[13].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[0],
                    array[1],
                    array[2],
                    array[3]
                }, 0)),
                lut[14].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[4],
                    array[5],
                    array[6],
                    array[7]
                }, 0)),
                lut[15].LookUp(BitConverter.ToUInt32(new byte[]
                {
                    array[8],
                    array[9],
                    array[10],
                    array[11]
                }, 0))
            };
        }

        public static byte[] GetNGKey(string name, uint length)
        {
            uint num = (GTA5Hash.CalculateHash(name) + length + 61U) % 101U;
            return GTA5Constants.PC_NG_KEYS[(int)num];
        }
    }

    public class GTA5Hash
    {
        public static byte[] LUT;

        static GTA5Hash()
        {
            LUT = GTA5Constants.PC_LUT;
        }

        public static uint CalculateHash(string text)
        {
            uint result = 0;
            for (int index = 0; index < text.Length; index++)
            {
                var temp = 1025 * (LUT[text[index]] + result);
                result = (temp >> 6) ^ temp;
            }
            return 32769 * ((9 * result >> 11) ^ 9 * result);
        }
    }
}
