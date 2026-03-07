using v1mertool.Crypto;
using v1mertool.Helper;

namespace v1mertool.Archives
{
    public class DataBlock
    {
        public long Offset { get; set; }
        public long Length { get; set; }
        public object Tag { get; set; }

        public DataBlock(long offset, long length, object tag = null)
        {
            this.Offset = offset;
            this.Length = length;
            this.Tag = tag;
        }
    }

    public static class ArchiveHelpers
    {
        private const int BUFFER_SIZE = 16384;
        public static long FindSpace(List<DataBlock> blocks, DataBlock item)
        {
            blocks.Sort(
                delegate (DataBlock a, DataBlock b)
                {
                    if (a.Offset != b.Offset)
                        return a.Offset.CompareTo(b.Offset);
                    else
                        return a.Offset.CompareTo(b.Offset);
                }
            );

            DataBlock next = null;
            foreach (var x in blocks)
            {
                if ((x != item) && (x.Offset >= item.Offset))
                {
                    if (next == null)
                    {
                        next = x;
                    }
                    else
                    {
                        if (x.Offset < next.Offset)
                            next = x;
                    }
                }

            }

            if (next == null)
                return long.MaxValue;

            return next.Offset - item.Offset;
        }

        public static long FindOffset(List<DataBlock> blocks, long neededSpace, long blockSize = 1)
        {
            var lst = new List<DataBlock>();
            lst.AddRange(blocks);

            lst.Sort(
                delegate (DataBlock a, DataBlock b)
                {
                    if (a.Offset != b.Offset)
                        return a.Offset.CompareTo(b.Offset);
                    else
                        return a.Offset.CompareTo(b.Offset);
                }
            );

            if (lst.Count == 0)
                return 0;

            for (int i = 0; i < lst.Count - 1; i++)
            {
                lst[i].Length = Math.Min(lst[i].Length, lst[i + 1].Offset - lst[i].Offset);
            }

            long offset = 0;
            for (int i = 0; i < lst.Count; i++)
            {
                long len = lst[i].Offset - offset;
                if (len >= neededSpace)
                    return offset;

                offset = lst[i].Offset + lst[i].Length;
                offset = (long)Math.Ceiling((double)offset / (double)blockSize) * blockSize;
            }

            return offset;
        }

        public static void MoveBytes(Stream stream, long sourceOffset, long destinationOffset, long length)
        {
            var buffer = new byte[BUFFER_SIZE];
            while (length > 0)
            {
                stream.Position = sourceOffset;
                int i = stream.Read(buffer, 0, (int)Math.Min(length, BUFFER_SIZE));

                stream.Position = destinationOffset;
                stream.Write(buffer, 0, i);

                sourceOffset += i;
                destinationOffset += i;
                length -= i;
            }
        }
    }

    public interface IArchive : IDisposable
    {
        IArchiveDirectory Root { get; }
        void Flush();
    }

    public interface IArchiveDirectory
    {
        string Name { get; set; }
        IArchiveDirectory[] GetDirectories();
        IArchiveDirectory GetDirectory(string name);
        IArchiveDirectory CreateDirectory();
        void DeleteDirectory(IArchiveDirectory directory);
        IArchiveFile[] GetFiles();
        IArchiveFile GetFile(string name);
        void DeleteFile(IArchiveFile file);
    }

    public interface IArchiveFile
    {
        string Name { get; set; }
        long Size { get; }
    }
    public interface IArchiveBinaryFile : IArchiveFile
    {
        bool IsEncrypted { get; set; }
        bool IsCompressed { get; set; }
        long UncompressedSize { get; set; }
        long CompressedSize { get; }
    }


    public interface IRageArchiveEntry7
    {
        uint NameOffset { get; set; }
        string Name { get; set; }
        void Read(DataReader reader);
        void Write(DataWriter writer);
    }

    public interface IRageArchiveFileEntry7 : IRageArchiveEntry7
    {
        uint FileOffset { get; set; }
        uint FileSize { get; set; }
    }

    public class RageArchive7 : IDisposable
    {
        public RageArchiveEncryption7 Encryption { get; set; }
        public Stream BaseStream { get; private set; }
        public RageArchiveDirectory7 Root { get; set; }
        public RageArchive7(Stream fileStream, bool leaveOpen = false)
        {
            this.BaseStream = fileStream;
            this.LeaveOpen = leaveOpen;
        }

        public void ReadHeader(byte[] ngKey = null)
        {
            var reader = new DataReader(BaseStream);
            var posbak = reader.Position;
            reader.Position = 0;

            uint header_identifier = reader.ReadUInt32();
            if (header_identifier != IDENT)
                throw new Exception("The identifier " + header_identifier.ToString("X8") + " did not match the expected value of 0x52504637");

            uint header_entriesCount = reader.ReadUInt32();
            uint rawNamesLength = reader.ReadUInt32();
            bool isXCompressed = (rawNamesLength & 0x80000000) != 0;
            uint header_namesLength = rawNamesLength & 0x0FFFFFFF;
            uint header_encryption = reader.ReadUInt32();

            byte[] entries_data_dec = null;
            byte[] names_data_dec = null;

            if (header_encryption == 0x04E45504F)
            {
                Encryption = RageArchiveEncryption7.None;
                entries_data_dec = reader.ReadBytes(16 * (int)header_entriesCount);
                names_data_dec = reader.ReadBytes((int)header_namesLength);
            }
            else
            {
                Encryption = RageArchiveEncryption7.NG;
                var entries_data = reader.ReadBytes(16 * (int)header_entriesCount);
                entries_data_dec = GTA5Crypto.Decrypt(entries_data, ngKey);

                var names_data = reader.ReadBytes((int)header_namesLength);
                names_data_dec = GTA5Crypto.Decrypt(names_data, ngKey);
            }

            var entries_reader = new DataReader(new MemoryStream(entries_data_dec));
            var names_reader = new DataReader(new MemoryStream(names_data_dec));
            var entries = new List<IRageArchiveEntry7>();

            for (var index = 0; index < header_entriesCount; index++)
            {
                entries_reader.Position += 4;
                int x = entries_reader.ReadInt32();
                entries_reader.Position -= 8;

                if (x == 0x7fffff00)
                {
                    var e = new RageArchiveDirectory7();
                    e.Read(entries_reader);
                    names_reader.Position = e.NameOffset;
                    e.Name = names_reader.ReadString();
                    entries.Add(e);
                }
                else
                {
                    if ((x & 0x80000000) == 0)
                    {
                        var e = new RageArchiveBinaryFile7();
                        e.Read(entries_reader);
                        names_reader.Position = e.NameOffset;
                        e.Name = names_reader.ReadString();
                        entries.Add(e);
                    }
                    else
                    {
                        var e = new RageArchiveResourceFile7();
                        e.Read(entries_reader);
                        if (e.FileSize == 0xFFFFFF)
                        {
                            var currentPos = reader.Position;
                            reader.Position = 512 * e.FileOffset;
                            var buf = reader.ReadBytes(16);
                            e.FileSize = ((uint)buf[7] << 0) | ((uint)buf[14] << 8) | ((uint)buf[5] << 16) | ((uint)buf[2] << 24);
                            reader.Position = currentPos;
                        }
                        names_reader.Position = e.NameOffset;
                        e.Name = names_reader.ReadString();
                        entries.Add(e);
                    }
                }
            }

            var stack = new Stack<RageArchiveDirectory7>();
            stack.Push((RageArchiveDirectory7)entries[0]);
            Root = (RageArchiveDirectory7)entries[0];
            while (stack.Count > 0)
            {
                var item = stack.Pop();
                for (int index = (int)item.EntriesIndex; index < (item.EntriesIndex + item.EntriesCount); index++)
                {
                    if (entries[index] is RageArchiveDirectory7)
                    {
                        var dir = entries[index] as RageArchiveDirectory7;
                        item.Directories.Add(dir);
                        stack.Push(dir);
                    }
                    else
                    {
                        item.Files.Add(entries[index]);
                    }
                }
            }

            reader.Position = posbak;
        }
        public void WriteHeader(byte[] ngKey = null)
        {
            long position = this.BaseStream.Position;
            DataWriter dataWriter = new DataWriter(this.BaseStream, Endianess.LittleEndian);
            List<IRageArchiveEntry7> list = new List<IRageArchiveEntry7>();
            Stack<RageArchiveDirectory7> stack = new Stack<RageArchiveDirectory7>();
            int num = 1;
            list.Add(this.Root);
            stack.Push(this.Root);
            Dictionary<string, uint> dictionary = new Dictionary<string, uint>();
            dictionary.Add("", 0U);
            while (stack.Count > 0)
            {
                RageArchiveDirectory7 rageArchiveDirectory = stack.Pop();
                rageArchiveDirectory.EntriesIndex = (uint)list.Count;
                rageArchiveDirectory.EntriesCount = (uint)(rageArchiveDirectory.Directories.Count + rageArchiveDirectory.Files.Count);
                List<IRageArchiveEntry7> list2 = new List<IRageArchiveEntry7>();
                foreach (RageArchiveDirectory7 rageArchiveDirectory2 in rageArchiveDirectory.Directories)
                {
                    if (!dictionary.ContainsKey(rageArchiveDirectory2.Name))
                    {
                        dictionary.Add(rageArchiveDirectory2.Name, (uint)num);
                        num += rageArchiveDirectory2.Name.Length + 1;
                    }
                    rageArchiveDirectory2.NameOffset = dictionary[rageArchiveDirectory2.Name];
                    list2.Add(rageArchiveDirectory2);
                }
                foreach (IRageArchiveEntry7 rageArchiveEntry in rageArchiveDirectory.Files)
                {
                    if (!dictionary.ContainsKey(rageArchiveEntry.Name))
                    {
                        dictionary.Add(rageArchiveEntry.Name, (uint)num);
                        num += rageArchiveEntry.Name.Length + 1;
                    }
                    rageArchiveEntry.NameOffset = dictionary[rageArchiveEntry.Name];
                    list2.Add(rageArchiveEntry);
                }
                list2.Sort((IRageArchiveEntry7 a, IRageArchiveEntry7 b) => string.CompareOrdinal(a.Name, b.Name));
                foreach (IRageArchiveEntry7 item in list2)
                {
                    list.Add(item);
                }
                list2.Reverse();
                foreach (IRageArchiveEntry7 rageArchiveEntry2 in list2)
                {
                    if (rageArchiveEntry2 is RageArchiveDirectory7)
                    {
                        stack.Push((RageArchiveDirectory7)rageArchiveEntry2);
                    }
                }
            }
            foreach (IRageArchiveEntry7 rageArchiveEntry3 in list)
            {
                if (rageArchiveEntry3 is RageArchiveResourceFile7)
                {
                    RageArchiveResourceFile7 rageArchiveResourceFile = rageArchiveEntry3 as RageArchiveResourceFile7;
                    if (rageArchiveResourceFile.FileSize > 16777215U)
                    {
                        byte[] array = new byte[16];
                        array[7] = (byte)(rageArchiveResourceFile.FileSize & 255U);
                        array[14] = (byte)(rageArchiveResourceFile.FileSize >> 8 & 255U);
                        array[5] = (byte)(rageArchiveResourceFile.FileSize >> 16 & 255U);
                        array[2] = (byte)(rageArchiveResourceFile.FileSize >> 24 & 255U);
                        if (dataWriter.Length > (long)((ulong)(512U * rageArchiveResourceFile.FileOffset)))
                        {
                            dataWriter.Position = (long)((ulong)(512U * rageArchiveResourceFile.FileOffset));
                            dataWriter.Write(array);
                        }
                        rageArchiveResourceFile.FileSize = 16777215U;
                    }
                }
            }
            MemoryStream memoryStream = new MemoryStream();
            DataWriter writer = new DataWriter(memoryStream, Endianess.LittleEndian);
            foreach (IRageArchiveEntry7 rageArchiveEntry4 in list)
            {
                rageArchiveEntry4.Write(writer);
            }
            memoryStream.Flush();
            byte[] array2 = new byte[memoryStream.Length];
            memoryStream.Position = 0L;
            memoryStream.Read(array2, 0, array2.Length);
            if (this.Encryption == RageArchiveEncryption7.NG)
            {
                array2 = GTA5Crypto.Encrypt(array2, ngKey);
            }
            MemoryStream memoryStream2 = new MemoryStream();
            DataWriter dataWriter2 = new DataWriter(memoryStream2, Endianess.LittleEndian);
            foreach (KeyValuePair<string, uint> keyValuePair in dictionary)
            {
                dataWriter2.Write(keyValuePair.Key);
            }
            byte[] value = new byte[16L - dataWriter2.Length % 16L];
            dataWriter2.Write(value);
            memoryStream2.Flush();
            byte[] array3 = new byte[memoryStream2.Length];
            memoryStream2.Position = 0L;
            memoryStream2.Read(array3, 0, array3.Length);
            if (this.Encryption == RageArchiveEncryption7.NG)
            {
                array3 = GTA5Crypto.Encrypt(array3, ngKey);
            }
            dataWriter.Position = 0L;
            dataWriter.Write(1380992567);
            dataWriter.Write((uint)list.Count);
            dataWriter.Write((uint)array3.Length);
            switch (this.Encryption)
            {
                case RageArchiveEncryption7.None:
                    dataWriter.Write(1313165391);
                    break;
                case RageArchiveEncryption7.NG:
                    dataWriter.Write(267386879);
                    break;
            }
            dataWriter.Write(array2);
            dataWriter.Write(array3);
            this.BaseStream.Position = position;
        }
        public void Dispose()
        {
            if (this.BaseStream != null)
            {
                this.BaseStream.Dispose();
            }
            this.BaseStream = null;
            this.Root = null;
        }

        private const uint IDENT = 1380992567U;
        private bool LeaveOpen;
    }

    public class RageArchiveBinaryFile7 : IRageArchiveFileEntry7, IRageArchiveEntry7
    {
        public uint NameOffset { get; set; }
        public uint FileSize { get; set; }
        public uint FileOffset { get; set; }
        public uint FileUncompressedSize { get; set; }
        public uint Flags { get; set; }
        public bool IsEncrypted
        {
            get
            {
                return (this.Flags & 1U) == 1U;
            }
            set
            {
                if (value)
                {
                    this.Flags |= 1U;
                    return;
                }
                this.Flags &= 4294967294U;
            }
        }
        public string Name { get; set; }

        public void Read(DataReader reader)
        {
            ulong num = reader.ReadUInt64();
            this.NameOffset = (uint)num & 65535U;
            this.FileSize = (uint)(num >> 16) & 16777215U;
            this.FileOffset = (uint)(num >> 40) & 16777215U;
            this.FileUncompressedSize = reader.ReadUInt32();
            this.Flags = reader.ReadUInt32();
        }
        public void Write(DataWriter writer)
        {
            writer.Write((ushort)this.NameOffset);
            byte[] value = new byte[]
            {
                (byte)(this.FileSize & 255U),
                (byte)(this.FileSize >> 8 & 255U),
                (byte)(this.FileSize >> 16 & 255U)
            };
            writer.Write(value);
            byte[] value2 = new byte[]
            {
                (byte)(this.FileOffset & 255U),
                (byte)(this.FileOffset >> 8 & 255U),
                (byte)(this.FileOffset >> 16 & 255U)
            };
            writer.Write(value2);
            writer.Write(this.FileUncompressedSize);
            if (this.IsEncrypted)
            {
                writer.Write(13U);
                return;
            }
            writer.Write(0U);
        }
    }

    public class RageArchiveDirectory7 : IRageArchiveEntry7
    {
        public uint NameOffset { get; set; }
        public uint EntriesIndex { get; set; }
        public uint EntriesCount { get; set; }
        public string Name { get; set; }
        public void Read(DataReader reader)
        {
            this.NameOffset = reader.ReadUInt32();
            if (reader.ReadUInt32() != 2147483392U)
            {
                throw new Exception("Error in RPF7 directory entry.");
            }
            this.EntriesIndex = reader.ReadUInt32();
            this.EntriesCount = reader.ReadUInt32();
        }

        public void Write(DataWriter writer)
        {
            writer.Write(this.NameOffset);
            writer.Write(2147483392U);
            writer.Write(this.EntriesIndex);
            writer.Write(this.EntriesCount);
        }

        public List<RageArchiveDirectory7> Directories = new List<RageArchiveDirectory7>();
        public List<IRageArchiveEntry7> Files = new List<IRageArchiveEntry7>();
    }

    public enum RageArchiveEncryption7
    {
        None,
        NG
    }

    public class RageArchiveResourceFile7 : IRageArchiveFileEntry7, IRageArchiveEntry7
    {
        public uint NameOffset { get; set; }
        public uint FileSize { get; set; }
        public uint FileOffset { get; set; }
        public uint SystemFlags { get; set; }
        public uint GraphicsFlags { get; set; }
        public string Name { get; set; }

        public void Read(DataReader reader)
        {
            this.NameOffset = (uint)reader.ReadUInt16();
            byte[] array = reader.ReadBytes(3);
            this.FileSize = (uint)((int)array[0] + ((int)array[1] << 8) + ((int)array[2] << 16));
            byte[] array2 = reader.ReadBytes(3);
            this.FileOffset = (uint)((int)array2[0] + ((int)array2[1] << 8) + ((int)array2[2] << 16) & 8388607);
            this.SystemFlags = reader.ReadUInt32();
            this.GraphicsFlags = reader.ReadUInt32();
        }

        public void Write(DataWriter writer)
        {
            writer.Write((ushort)this.NameOffset);
            byte[] value = new byte[]
            {
                (byte)(this.FileSize & 255U),
                (byte)(this.FileSize >> 8 & 255U),
                (byte)(this.FileSize >> 16 & 255U)
            };
            writer.Write(value);
            byte[] value2 = new byte[]
            {
                (byte)(this.FileOffset & 255U),
                (byte)(this.FileOffset >> 8 & 255U),
                (byte)((this.FileOffset >> 16 & 255U) | 128U)
            };
            writer.Write(value2);
            writer.Write(this.SystemFlags);
            writer.Write(this.GraphicsFlags);
        }
    }

    public class RageArchiveWrapper7 : IArchive
    {
        public static int BLOCK_SIZE = 512;

        public RageArchive7 archive_;

        public string FileName { get; set; }

        public IArchiveDirectory Root
        {
            get { return new RageArchiveDirectoryWrapper7(this, archive_.Root); }
        }

        private RageArchiveWrapper7(Stream stream, string fileName, bool leaveOpen = false)
        {
            archive_ = new RageArchive7(stream, leaveOpen);
            this.FileName = fileName;
        }

        public void Flush()
        {

            long headerSize = GetHeaderSize();
            do
            {
                var blocks = GetBlocks();
                long maxheaderlength = ArchiveHelpers.FindSpace(blocks, blocks[0]);
                if (maxheaderlength < headerSize)
                {
                    long newpos = ArchiveHelpers.FindOffset(blocks, blocks[1].Length, 512);
                    ArchiveHelpers.MoveBytes(archive_.BaseStream, blocks[1].Offset, newpos, blocks[1].Length);
                    ((IRageArchiveFileEntry7)blocks[1].Tag).FileOffset = (uint)(newpos / 512);

                    blocks = GetBlocks();
                    maxheaderlength = ArchiveHelpers.FindSpace(blocks, blocks[0]);
                }
                else
                    break;

            } while (true);

            var tmp1 = GTA5Hash.CalculateHash(FileName);
            var tmp2 = (tmp1 + (uint)archive_.BaseStream.Length + (101 - 40)) % 0x65;

            archive_.WriteHeader(GTA5Constants.PC_NG_KEYS[tmp2]);
            archive_.BaseStream.Flush();

        }

        public void Dispose()
        {
            if (archive_ != null)
                archive_.Dispose();

            archive_ = null;
        }


        private long GetHeaderSize()
        {
            long len = 16;

            var st = new Stack<RageArchiveDirectory7>();
            st.Push(archive_.Root);
            while (st.Count > 0)
            {
                var x = st.Pop();
                len += 16;
                len += x.Name.Length + 1;

                foreach (var q in x.Directories)
                    st.Push(q);
                foreach (var q in x.Files)
                    len += 16 + q.Name.Length + 1;
            }


            return len;
        }


        internal long FindSpace(long length)
        {
            long x = GetHeaderSize();

            List<DataBlock> blocks = GetBlocks();

            long offset = ArchiveHelpers.FindOffset(blocks, length, 512);
            return offset;
        }

        private List<DataBlock> GetBlocks()
        {
            var blocks = new List<DataBlock>();

            blocks.Add(
                new DataBlock(0, GetHeaderSize())
            );

            var st = new Stack<RageArchiveDirectory7>();
            st.Push(archive_.Root);
            while (st.Count > 0)
            {
                var x = st.Pop();

                foreach (var q in x.Directories)
                    st.Push(q);
                foreach (IRageArchiveFileEntry7 q in x.Files)
                {
                    if (q is RageArchiveBinaryFile7)
                    {
                        RageArchiveBinaryFile7 fff = (RageArchiveBinaryFile7)q;

                        long l = 0;
                        if (q.FileSize == 0)
                            l = fff.FileUncompressedSize;
                        else
                            l = fff.FileSize;

                        blocks.Add(new DataBlock(q.FileOffset * 512, l, q));
                    }
                    else
                    {
                        RageArchiveResourceFile7 fff = (RageArchiveResourceFile7)q;

                        long l = fff.FileSize;

                        blocks.Add(new DataBlock(q.FileOffset * 512, l, q));
                    }
                }
            }

            blocks.Sort(
                        delegate (DataBlock a, DataBlock b)
                        {
                            if (a.Offset != b.Offset)
                                return a.Offset.CompareTo(b.Offset);
                            else
                                return a.Offset.CompareTo(b.Offset);
                        }
                    );

            return blocks;
        }



        public void RequestBytes(RageArchiveBinaryFile7 file_, long newLength)
        {
            long x = GetHeaderSize();

            DataBlock thisBlock = null;
            var blocks = GetBlocks();
            foreach (var q in blocks)
                if (q.Tag == file_)
                    thisBlock = q;

            long maxlength = ArchiveHelpers.FindSpace(blocks, thisBlock);
            if (maxlength < newLength)
            {
                long offset = ArchiveHelpers.FindOffset(blocks, newLength, 512);
                ArchiveHelpers.MoveBytes(archive_.BaseStream, thisBlock.Offset, offset, thisBlock.Length);
                ((IRageArchiveFileEntry7)thisBlock.Tag).FileOffset = (uint)offset / 512;

            }

            if (file_.FileSize != 0)
                file_.FileSize = (uint)newLength;
            else
                file_.FileUncompressedSize = (uint)newLength;
        }

        public void RequestBytesRES(RageArchiveResourceFile7 file_, long newLength)
        {
            long x = GetHeaderSize();

            DataBlock thisBlock = null;
            List<DataBlock> blocks = GetBlocks();
            foreach (var q in blocks)
                if (q.Tag == file_)
                    thisBlock = q;

            long maxlength = ArchiveHelpers.FindSpace(blocks, thisBlock);
            if (maxlength < newLength)
            {
                long offset = ArchiveHelpers.FindOffset(blocks, newLength, 512);
                ArchiveHelpers.MoveBytes(archive_.BaseStream, thisBlock.Offset, offset, thisBlock.Length);
                ((IRageArchiveFileEntry7)thisBlock.Tag).FileOffset = (uint)offset / 512;

            }

            file_.FileSize = (uint)newLength;
        }

        public static RageArchiveWrapper7 Create(string fileName)
        {
            var finfo = new FileInfo(fileName);
            var fs = new FileStream(fileName, FileMode.Create);
            var arch = new RageArchiveWrapper7(fs, finfo.Name, false);


            var rootD = new RageArchiveDirectory7();
            rootD.Name = "";
            arch.archive_.Root = rootD;

            return arch;
        }

        public static RageArchiveWrapper7 Create(Stream stream, string fileName, bool leaveOpen = false)
        {
            var arch = new RageArchiveWrapper7(stream, fileName, leaveOpen);


            var rootD = new RageArchiveDirectory7();
            rootD.Name = "";
            arch.archive_.Root = rootD;

            return arch;
        }

        public static RageArchiveWrapper7 Open(string fileName)
        {
            var finfo = new FileInfo(fileName);
            var fs = new FileStream(fileName, FileMode.Open);
            var arch = new RageArchiveWrapper7(fs, finfo.Name, false);
            try
            {

                if (GTA5Constants.PC_LUT != null && GTA5Constants.PC_NG_KEYS != null)
                {
                    var tmp1 = GTA5Hash.CalculateHash(arch.FileName);
                    var tmp2 = (tmp1 + (uint)finfo.Length + (101 - 40)) % 0x65;

                    arch.archive_.ReadHeader(GTA5Constants.PC_NG_KEYS[tmp2]);
                }


                return arch;
            }
            catch
            {
                fs.Dispose();
                arch.Dispose();
                throw;
            }
        }

        public static RageArchiveWrapper7 Open(Stream stream, string fileName, bool leaveOpen = false)
        {
            var arch = new RageArchiveWrapper7(stream, fileName, leaveOpen);
            try
            {
                if (GTA5Constants.PC_LUT != null && GTA5Constants.PC_NG_KEYS != null)
                {
                    var tmp1 = GTA5Hash.CalculateHash(arch.FileName);
                    var tmp2 = (tmp1 + (uint)stream.Length + (101 - 40)) % 0x65;

                    arch.archive_.ReadHeader(GTA5Constants.PC_NG_KEYS[tmp2]);
                }

                return arch;
            }
            catch
            {
                arch.Dispose();
                throw;
            }
        }
    }

    public class RageArchiveDirectoryWrapper7 : IArchiveDirectory, IDisposable
    {
        private RageArchiveWrapper7 archiveWrapper;
        internal RageArchiveDirectory7 directory;

        public string Name
        {
            get
            {
                return directory.Name;
            }
            set
            {
                directory.Name = value;
            }
        }

        internal RageArchiveDirectoryWrapper7(RageArchiveWrapper7 archiveWrapper, RageArchiveDirectory7 directory)
        {
            this.archiveWrapper = archiveWrapper;
            this.directory = directory;
        }

        public IArchiveDirectory[] GetDirectories()
        {
            var directoryList = new List<IArchiveDirectory>();
            foreach (var directory in directory.Directories)
            {
                var directoryWrapper = new RageArchiveDirectoryWrapper7(archiveWrapper, directory);
                directoryList.Add(directoryWrapper);
            }
            return directoryList.ToArray();
        }

        public IArchiveDirectory GetDirectory(string name)
        {
            foreach (var directory in directory.Directories)
            {
                if (directory.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return new RageArchiveDirectoryWrapper7(archiveWrapper, directory);
            }
            return null;
        }

        public IArchiveDirectory CreateDirectory()
        {
            var newDirectory = new RageArchiveDirectory7();
            var newDirectoryWrapper = new RageArchiveDirectoryWrapper7(archiveWrapper, newDirectory);

            this.directory.Directories.Add(newDirectory);

            return newDirectoryWrapper;
        }

        public void DeleteDirectory(IArchiveDirectory directory)
        {
            this.directory.Directories.Remove(((RageArchiveDirectoryWrapper7)directory).directory);
        }

        public IArchiveFile[] GetFiles()
        {
            var fileList = new List<IArchiveFile>();
            foreach (var rawFile in directory.Files)
            {
                if (rawFile is RageArchiveBinaryFile7)
                    fileList.Add(new RageArchiveBinaryFileWrapper7(archiveWrapper, (RageArchiveBinaryFile7)rawFile));
            }
            return fileList.ToArray();
        }

        public IArchiveFile GetFile(string name)
        {
            foreach (var f in directory.Files)
            {
                if (f.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    if (f is RageArchiveResourceFile7)
                        return new RageArchiveBinaryFileWrapper7(archiveWrapper, (RageArchiveBinaryFile7)f);
            }
            return null;
        }

        public void DeleteFile(IArchiveFile file)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            this.archiveWrapper = null;
            this.directory = null;
        }
    }

    public class RageArchiveBinaryFileWrapper7 : IArchiveBinaryFile
    {
        internal RageArchiveWrapper7 archiveWrapper;
        internal RageArchiveBinaryFile7 file;

        public string Name
        {
            get
            {
                return file.Name;
            }
            set
            {
                file.Name = value;
            }
        }

        public bool IsEncrypted
        {
            get
            {
                return file.IsEncrypted;
            }
            set
            {
                file.IsEncrypted = value;
            }
        }

        public bool IsCompressed
        {
            get
            {
                return file.FileSize != 0;
            }
            set
            {
                if (value)
                {
                    file.FileSize = file.FileUncompressedSize;
                }
                else
                {
                    file.FileUncompressedSize = file.FileSize;
                    file.FileSize = 0;
                }
            }
        }

        public long UncompressedSize
        {
            get
            {
                return file.FileUncompressedSize;
            }
            set
            {
                file.FileUncompressedSize = (uint)value;
            }
        }

        public long CompressedSize
        {
            get
            {
                return file.FileSize;
            }
        }

        public long Size
        {
            get
            {
                if (file.FileSize != 0)
                    return file.FileSize;
                else
                    return file.FileUncompressedSize;
            }
        }

        internal RageArchiveBinaryFileWrapper7(RageArchiveWrapper7 archiveWrapper, RageArchiveBinaryFile7 file)
        {
            this.archiveWrapper = archiveWrapper;
            this.file = file;
        }

    }
}
