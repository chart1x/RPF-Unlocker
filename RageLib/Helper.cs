using System.Security.Cryptography;
using v1mertool.Crypto;
using System.Text;

namespace v1mertool.Helper
{
    public class KeyNotFoundException : Exception
    {
        public KeyNotFoundException() : base()
        { }

        public KeyNotFoundException(string message) : base(message)
        { }
    }

    public class GTA5NGLUT
    {
        public GTA5NGLUT()
        {
            this.LUT0 = new byte[256][];
            for (int i = 0; i < 256; i++)
            {
                this.LUT0[i] = new byte[256];
            }
            this.LUT1 = new byte[256][];
            for (int j = 0; j < 256; j++)
            {
                this.LUT1[j] = new byte[256];
            }
            this.Indices = new byte[65536];
        }

        public byte LookUp(uint value)
        {
            uint num = (value & 4294901760U) >> 16;
            uint num2 = (value & 65280U) >> 8;
            uint num3 = value & 255U;
            return this.LUT0[(int)this.LUT1[(int)this.Indices[(int)num]][(int)num2]][(int)num3];
        }

        public byte[][] LUT0;

        public byte[][] LUT1;

        public byte[] Indices;
    }

    public class CryptoIO
    {

        public static byte[][] ReadNgKeys(string fileName)
        {
            FileStream fileStream = new FileStream(fileName, FileMode.Open);
            DataReader dataReader = new DataReader(fileStream, Endianess.LittleEndian);
            byte[][] array = new byte[101][];
            for (int i = 0; i < 101; i++)
            {
                array[i] = dataReader.ReadBytes(272);
            }
            fileStream.Close();
            return array;
        }
        public static uint[][][] ReadNgTables(string fileName)
        {
            FileStream fileStream = new FileStream(fileName, FileMode.Open);
            DataReader dataReader = new DataReader(fileStream, Endianess.LittleEndian);
            uint[][][] array = new uint[17][][];
            for (int i = 0; i < 17; i++)
            {
                array[i] = new uint[16][];
                for (int j = 0; j < 16; j++)
                {
                    array[i][j] = new uint[256];
                    for (int k = 0; k < 256; k++)
                    {
                        array[i][j][k] = dataReader.ReadUInt32();
                    }
                }
            }
            fileStream.Close();
            return array;
        }

        public static GTA5NGLUT[][] ReadNgLuts(byte[] data)
        {
            MemoryStream memoryStream = new MemoryStream(data);
            DataReader dataReader = new DataReader(memoryStream, Endianess.LittleEndian);
            GTA5NGLUT[][] array = new GTA5NGLUT[17][];
            for (int i = 0; i < 17; i++)
            {
                array[i] = new GTA5NGLUT[16];
                for (int j = 0; j < 16; j++)
                {
                    array[i][j] = new GTA5NGLUT();
                    array[i][j].LUT0 = new byte[256][];
                    for (int k = 0; k < 256; k++)
                    {
                        array[i][j].LUT0[k] = dataReader.ReadBytes(256);
                    }
                    array[i][j].LUT1 = new byte[256][];
                    for (int l = 0; l < 256; l++)
                    {
                        array[i][j].LUT1[l] = dataReader.ReadBytes(256);
                    }
                    array[i][j].Indices = dataReader.ReadBytes(65536);
                }
            }
            memoryStream.Close();
            return array;
        }

        public static GTA5NGLUT[][] ReadNgLuts(string fileName)
        {
            return CryptoIO.ReadNgLuts(File.ReadAllBytes(fileName));
        }
    }

    public class DataReader
    {
        private Stream baseStream;

        public Endianess Endianess
        {
            get;
            set;
        }

        public virtual long Position
        {
            get
            {
                return baseStream.Position;
            }
            set
            {
                baseStream.Position = value;
            }
        }

        public DataReader(Stream stream, Endianess endianess = Endianess.LittleEndian)
        {
            this.baseStream = stream;
            this.Endianess = endianess;
        }

        protected virtual byte[] ReadFromStream(int count, bool ignoreEndianess = false)
        {
            var buffer = new byte[count];
            baseStream.Read(buffer, 0, count);

            if (!ignoreEndianess && (Endianess == Endianess.BigEndian))
            {
                Array.Reverse(buffer);
            }

            return buffer;
        }

        public byte[] ReadBytes(int count)
        {
            return ReadFromStream(count, true);
        }

        public int ReadInt32()
        {
            return BitConverter.ToInt32(ReadFromStream(4), 0);
        }

        public ushort ReadUInt16()
        {
            return BitConverter.ToUInt16(ReadFromStream(2), 0);
        }

        public uint ReadUInt32()
        {
            return BitConverter.ToUInt32(ReadFromStream(4), 0);
        }
        public ulong ReadUInt64()
        {
            return BitConverter.ToUInt64(this.ReadFromStream(8, false), 0);
        }

        public string ReadString()
        {
            var bytes = new List<byte>();
            var temp = ReadFromStream(1)[0];
            while (temp != 0)
            {
                bytes.Add(temp);
                temp = ReadFromStream(1)[0];
            }

            return Encoding.UTF8.GetString(bytes.ToArray());
        }
    }

    public class DataWriter
    {
        private Stream baseStream;

        public Endianess Endianess
        {
            get;
            set;
        }

        public virtual long Length
        {
            get
            {
                return baseStream.Length;
            }
        }

        public virtual long Position
        {
            get
            {
                return baseStream.Position;
            }
            set
            {
                baseStream.Position = value;
            }
        }

        public DataWriter(Stream stream, Endianess endianess = Endianess.LittleEndian)
        {
            this.baseStream = stream;
            this.Endianess = endianess;
        }

        protected virtual void WriteToStream(byte[] value, bool ignoreEndianess = false)
        {
            if (!ignoreEndianess && (Endianess == Endianess.BigEndian))
            {
                var buffer = (byte[])value.Clone();
                Array.Reverse(buffer);
                baseStream.Write(buffer, 0, buffer.Length);
            }
            else
            {
                baseStream.Write(value, 0, value.Length);
            }
        }

        public void Write(byte value)
        {
            WriteToStream(new byte[] { value });
        }

        public void Write(byte[] value)
        {
            WriteToStream(value, true);
        }

        public void Write(int value)
        {
            WriteToStream(BitConverter.GetBytes(value));
        }

        public void Write(ushort value)
        {
            WriteToStream(BitConverter.GetBytes(value));
        }

        public void Write(uint value)
        {
            WriteToStream(BitConverter.GetBytes(value));
        }

        public void Write(string value)
        {
            foreach (var c in value)
                Write((byte)c);
            Write((byte)0);
        }
    }

    public enum Endianess
    {
        LittleEndian,
        BigEndian
    }

    public delegate long GetOffsetDelegate();
    public delegate long GetLengthDelegate();
    public delegate void SetLengthDelegate(long length);
}
