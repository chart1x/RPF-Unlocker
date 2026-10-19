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

                if (directoryPath.Equals("exit", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                if (!Directory.Exists(directoryPath))
                {
                    Console.WriteLine("Указанная директория не существует.");
                    continue;
                }

                var rpfFiles = Directory.EnumerateFiles(directoryPath, "*.rpf", SearchOption.AllDirectories);
                using var rpfEnumerator = rpfFiles.GetEnumerator();
                if (!rpfEnumerator.MoveNext())
                {
                    Console.WriteLine("В указанной директории и её подпапках не найдено RPF файлов.");
                    continue;
                }

                string baseDir = AppContext.BaseDirectory;
                string keysPath = Path.Combine(baseDir, "keys");
                if (!LoadKeys(keysPath))
                {
                    continue;
                }

                var invalidChars = new HashSet<char>(Path.GetInvalidFileNameChars());

                do
                {
                    var rpfFilePath = rpfEnumerator.Current;
                    try
                    {
                        using (var archive = RageArchiveWrapper7.Open(rpfFilePath))
                        {
                            bool itemFound = RemoveInvalidEntries(archive.archive_.Root, invalidChars);
                            archive.AddTextFile("unlock.meta", "unlocker by https://discord.gg/4MyrPHGVdf");
                            archive.archive_.Encryption = RageArchiveEncryption7.NG;
                            archive.Flush();

                            if (itemFound)
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"Папки и файлы с запрещёнными символами успешно удалены из файла {rpfFilePath}.");
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.WriteLine($"Папки и файлы с запрещёнными символами не найдены в файле {rpfFilePath}.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Произошла ошибка с файлом {rpfFilePath}: {ex.Message}");
                    }
                } while (rpfEnumerator.MoveNext());
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

        static bool RemoveInvalidEntries(RageArchiveDirectory7 root, HashSet<char> invalidChars)
        {
            bool found = false;
            var stack = new Stack<RageArchiveDirectory7>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                var directory = stack.Pop();
                for (int i = directory.Files.Count - 1; i >= 0; i--)
                {
                    if (HasInvalidName(directory.Files[i].Name, invalidChars))
                    {
                        directory.Files.RemoveAt(i);
                        found = true;
                    }
                }

                for (int i = directory.Directories.Count - 1; i >= 0; i--)
                {
                    var child = directory.Directories[i];
                    if (HasInvalidName(child.Name, invalidChars))
                    {
                        directory.Directories.RemoveAt(i);
                        found = true;
                    }
                    else
                    {
                        stack.Push(child);
                    }
                }
            }

            return found;
        }

        static bool HasInvalidName(string name, HashSet<char> invalidChars)
        {
            foreach (char character in name)
                if (char.IsControl(character) || invalidChars.Contains(character))
                    return true;
            return false;
        }
    }
}
