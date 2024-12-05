using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

class Program
{
    static void Main(string[] args)
    {
        while (true)
        {
            Console.Clear();
            Console.WriteLine("Выберите действие:");
            Console.WriteLine("1. Дешифровать файл");
            Console.WriteLine("2. Дешифровать папку");
            Console.WriteLine("3. Выйти");
            Console.Write("Ваш выбор: ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    {
                        byte[] key, iv;
                        // Запросить путь к файлу
                        Console.Write("Введите путь к зашифрованному файлу: ");
                        string decryptFilePath = Console.ReadLine().Trim('"');
                        if (File.Exists(decryptFilePath))
                        {
                            // Запросить пароль
                            Console.Write("Введите пароль для расшифровки: ");
                            string decryptPassword = Console.ReadLine();
                            GenerateKeyAndIV(decryptPassword, out key, out iv);

                            byte[] encryptedFileData = File.ReadAllBytes(decryptFilePath);
                            byte[] decryptedData = DecryptData(encryptedFileData, key, iv);

                            if (decryptedData != null)
                            {
                                // Запросить путь для сохранения
                                Console.Write("Введите путь для сохранения расшифрованного файла: ");
                                string decryptedFilePath = Console.ReadLine().Trim('"');

                                // Удалить расширение ".encrypted" при сохранении
                                decryptedFilePath = RemoveEncryptedExtension(decryptedFilePath);

                                try
                                {
                                    File.WriteAllBytes(decryptedFilePath, decryptedData);
                                    Console.WriteLine($"Файл расшифрован успешно: {decryptedFilePath}");
                                    File.Delete(decryptFilePath);
                                    Console.WriteLine($"Удален зашифрованный файл: {decryptFilePath}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Ошибка при записи расшифрованного файла: {ex.Message}");
                                }
                            }
                            else
                            {
                                Console.WriteLine("Не удалось расшифровать файл. Возможно, неправильный пароль.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Файл не найден.");
                        }
                        break;
                    }

                case "2":
                    {
                        byte[] key, iv;
                        // Запросить путь к папке
                        Console.Write("Введите путь к папке с зашифрованными файлами: ");
                        string decryptFolderPath = Console.ReadLine().Trim('"');
                        if (Directory.Exists(decryptFolderPath))
                        {
                            // Запросить пароль
                            Console.Write("Введите пароль для расшифровки: ");
                            string folderDecryptPassword = Console.ReadLine();
                            GenerateKeyAndIV(folderDecryptPassword, out key, out iv);

                            // Запросить путь для сохранения
                            Console.Write("Введите путь для сохранения расшифрованных файлов: ");
                            string outputFolderPath = Console.ReadLine().Trim('"');
                            DecryptDirectory(decryptFolderPath, key, iv, outputFolderPath);
                            Console.WriteLine("Все файлы в папке расшифрованы.");
                        }
                        else
                        {
                            Console.WriteLine("Папка не найдена.");
                        }
                        break;
                    }

                case "3":
                    return; // Выход из программы

                default:
                    Console.WriteLine("Неверный выбор.");
                    break;
            }

            Console.WriteLine("Нажмите любую клавишу для продолжения...");
            Console.ReadKey();
        }
    }

    static void DecryptDirectory(string directoryPath, byte[] key, byte[] iv, string outputDirectory)
    {
        if (!Directory.Exists(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
            Console.WriteLine($"Создана папка для сохранения расшифрованных файлов: {outputDirectory}");
        }

        foreach (var filePath in Directory.GetFiles(directoryPath))
        {
            if (filePath.EndsWith(".encrypted"))
            {
                try
                {
                    byte[] encryptedFileData = File.ReadAllBytes(filePath);
                    byte[] decryptedData = DecryptData(encryptedFileData, key, iv);
                    if (decryptedData != null)
                    {
                        string decryptedFilePath = Path.Combine(outputDirectory, Path.GetFileNameWithoutExtension(filePath));
                        File.WriteAllBytes(decryptedFilePath, decryptedData);
                        Console.WriteLine($"Файл расшифрован: {filePath}");

                        // Удаляем зашифрованный файл после расшифровки
                        File.Delete(filePath);
                        Console.WriteLine($"Удален зашифрованный файл: {filePath}");
                    }
                    else
                    {
                        Console.WriteLine($"Не удалось расшифровать файл: {filePath}. Возможно, неправильный пароль.");
                    }
                }
                catch (CryptographicException)
                {
                    Console.WriteLine($"Ошибка при расшифровке файла: {filePath}. Неверный пароль.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при обработке файла {filePath}: {ex.Message}");
                }
            }
        }

        foreach (var subDirectory in Directory.GetDirectories(directoryPath))
        {
            DecryptDirectory(subDirectory, key, iv, outputDirectory);
        }
    }

    static byte[] DecryptData(byte[] encryptedData, byte[] key, byte[] iv)
    {
        try
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encryptedData, 0, encryptedData.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
        catch (CryptographicException)
        {
            return null; // Неверный пароль
        }
        catch (Exception)
        {
            return null; // Ошибка
        }
    }

    static void GenerateKeyAndIV(string password, out byte[] key, out byte[] iv)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            key = hash.Take(16).ToArray(); // Используем только первые 16 байтов для ключа
            iv = hash.Skip(16).Take(16).ToArray(); // Следующие 16 байтов для вектора инициализации
        }
    }

    // Убирает расширение ".encrypted" (если оно есть)
    static string RemoveEncryptedExtension(string filePath)
    {
        // Если в имени файла есть расширение ".encrypted", удаляем его
        return filePath.EndsWith(".encrypted") ? Path.ChangeExtension(filePath, null) : filePath;
    }
}