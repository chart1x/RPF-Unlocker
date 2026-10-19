using System.Buffers.Binary;
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
            baseStream.ReadExactly(buffer);

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
            Span<byte> buffer = stackalloc byte[4];
            baseStream.ReadExactly(buffer);
            return Endianess == Endianess.LittleEndian
                ? BinaryPrimitives.ReadInt32LittleEndian(buffer)
                : BinaryPrimitives.ReadInt32BigEndian(buffer);
        }

        public ushort ReadUInt16()
        {
            Span<byte> buffer = stackalloc byte[2];
            baseStream.ReadExactly(buffer);
            return Endianess == Endianess.LittleEndian
                ? BinaryPrimitives.ReadUInt16LittleEndian(buffer)
                : BinaryPrimitives.ReadUInt16BigEndian(buffer);
        }

        public uint ReadUInt32()
        {
            Span<byte> buffer = stackalloc byte[4];
            baseStream.ReadExactly(buffer);
            return Endianess == Endianess.LittleEndian
                ? BinaryPrimitives.ReadUInt32LittleEndian(buffer)
                : BinaryPrimitives.ReadUInt32BigEndian(buffer);
        }
        public ulong ReadUInt64()
        {
            Span<byte> buffer = stackalloc byte[8];
            baseStream.ReadExactly(buffer);
            return Endianess == Endianess.LittleEndian
                ? BinaryPrimitives.ReadUInt64LittleEndian(buffer)
                : BinaryPrimitives.ReadUInt64BigEndian(buffer);
        }

        public string ReadString()
        {
            var bytes = new List<byte>();
            int value;
            while (true)
            {
                value = baseStream.ReadByte();
                if (value < 0)
                    throw new EndOfStreamException("Unexpected end of stream while reading a string.");
                if (value == 0)
                    break;
                bytes.Add((byte)value);
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
            Span<byte> buffer = stackalloc byte[1];
            buffer[0] = value;
            baseStream.Write(buffer);
        }

        public void Write(byte[] value)
        {
            WriteToStream(value, true);
        }

        public void Write(int value)
        {
            Span<byte> buffer = stackalloc byte[4];
            if (Endianess == Endianess.LittleEndian)
                BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
            else
                BinaryPrimitives.WriteInt32BigEndian(buffer, value);
            baseStream.Write(buffer);
        }

        public void Write(ushort value)
        {
            Span<byte> buffer = stackalloc byte[2];
            if (Endianess == Endianess.LittleEndian)
                BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
            else
                BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
            baseStream.Write(buffer);
        }

        public void Write(uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            if (Endianess == Endianess.LittleEndian)
                BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
            else
                BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            baseStream.Write(buffer);
        }

        public void Write(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            Write(bytes);
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
