using System.Reflection;
using System.Text;
using v1mertool.Archives;
using v1mertool.Crypto;

namespace RPFv7Editor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.Unicode;

            while (true)
            {
                Console.Write("Введите путь к директории для поиска RPF файлов (или 'exit' для выхода): ");
                string directoryPath = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(directoryPath))
                {
                    Console.WriteLine("Указанная директория не существует.");
                    continue;
                }

                if (directoryPath.ToLower() == "exit")
                {
                    break;
                }

                if (!Directory.Exists(directoryPath))
                {
                    Console.WriteLine("Указанная директория не существует.");
                    continue;
                }

                var rpfFiles = Directory.GetFiles(directoryPath, "*.rpf", SearchOption.AllDirectories);
                if (rpfFiles.Length == 0)
                {
                    Console.WriteLine("В указанной директории и её подпапках не найдено RPF файлов.");
                    continue;
                }

                string keysPath = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "keys");
                if (!LoadKeys(keysPath))
                {
                    continue;
                }

                var invalidChars = new HashSet<char>(Path.GetInvalidFileNameChars());

                foreach (var rpfFilePath in rpfFiles)
                {
                    try
                    {
                        UnfixArchive(rpfFilePath);
                        using (var archiveStream = new FileStream(rpfFilePath, FileMode.Open, FileAccess.ReadWrite))
                        {
                            var archive = new RageArchive7(archiveStream);
                            archive.ReadHeader();

                            bool itemFound = RemoveDirectoriesRecursive(archive.Root, invalidChars) | RemoveFilesRecursive(archive.Root, invalidChars);

                            if (itemFound)
                            {
                                archive.WriteHeader();
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"Папки и файлы с запрещёнными символами успешно удалены из файла {rpfFilePath}.");
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.WriteLine($"Папки и файлы с запрещёнными символами не найдены в файле {rpfFilePath}.");
                            }
                        }
                        FixArchive(rpfFilePath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Произошла ошибка с файлом {rpfFilePath}: {ex.Message}");
                    }
                }
            }
        }

        static bool LoadKeys(string keysPath)
        {
            try
            {
                GTA5Constants.LoadFromPath(keysPath);
                return true;
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Файл ключей не найден.");
                return false;
            }
        }

        static void UnfixArchive(string rpfFilePath)
        {
            if (string.IsNullOrWhiteSpace(rpfFilePath))
            {
                Console.WriteLine("Не указано имя архива.");
                return;
            }
            try
            {
                using (RageArchiveWrapper7 rageArchiveWrapper = RageArchiveWrapper7.Open(rpfFilePath))
                {
                    RageArchiveEncryption7 encryptionStatus = rageArchiveWrapper.archive_.Encryption;
                    if (encryptionStatus != RageArchiveEncryption7.NG)
                    {
                        Console.WriteLine("Ошибка. Архив уже расшифрован.");
                        return;
                    }
                    rageArchiveWrapper.archive_.Encryption = RageArchiveEncryption7.None;
                    rageArchiveWrapper.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Архив оказался сломанным: " + ex.Message);
            }
        }

        static void FixArchive(string rpfFilePath)
        {
            if (string.IsNullOrWhiteSpace(rpfFilePath))
            {
                Console.WriteLine("Не указано имя архива.");
                return;
            }
            try
            {
                using (RageArchiveWrapper7 rageArchiveWrapper = RageArchiveWrapper7.Open(rpfFilePath))
                {
                    RageArchiveEncryption7 encryptionStatus = rageArchiveWrapper.archive_.Encryption;
                    if (encryptionStatus != RageArchiveEncryption7.None)
                    {
                        Console.WriteLine("Ошибка. Архив уже зашифрован.");
                        return;
                    }
                    rageArchiveWrapper.archive_.Encryption = RageArchiveEncryption7.NG;
                    rageArchiveWrapper.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Архив оказался сломанным: " + ex.Message);
            }
        }

        static bool RemoveDirectoriesRecursive(RageArchiveDirectory7 directory, HashSet<char> invalidChars)
        {
            bool directoryFound = false;

            foreach (var dir in directory.Directories.ToList())
            {
                if (dir.Name.Any(ch => invalidChars.Contains(ch) || char.IsControl(ch)))
                {
                    directory.Directories.Remove(dir);
                    directoryFound = true;
                }
                else
                {
                    if (RemoveDirectoriesRecursive(dir, invalidChars))
                    {
                        directoryFound = true;
                    }
                }
            }

            return directoryFound;
        }

        static bool RemoveFilesRecursive(RageArchiveDirectory7 directory, HashSet<char> invalidChars)
        {
            bool fileFound = false;

            foreach (var file in directory.Files.ToList())
            {
                if (file.Name.Any(ch => invalidChars.Contains(ch) || char.IsControl(ch)))
                {
                    directory.Files.Remove(file);
                    fileFound = true;
                }
            }

            foreach (var dir in directory.Directories)
            {
                if (RemoveFilesRecursive(dir, invalidChars))
                {
                    fileFound = true;
                }
            }

            return fileFound;
        }
    }
}
