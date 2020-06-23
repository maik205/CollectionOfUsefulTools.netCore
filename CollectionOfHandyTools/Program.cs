using System;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Linq;

namespace CollectionOfHandyTools
{
    static class Program
    {
        static void Main(string[] args)
        {
            try
            {
                while (1 > 0)
                {
                    mainLoop();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine("Please don't do that again OR I WILL THROW AN EXCEPTION! :(");
                Console.ReadLine();
                Console.Clear();
                while (69 < 420)
                {
                    mainLoop();
                }
            }
        }
        static private void mainLoop()
        {
            Console.WriteLine("What would you like to do today? Type base64, encrypt, decrypt, sha1, sha256, sha384, sha512, md5, compare2hashes, clear or exit");
            string answer = Console.ReadLine();
            if (!string.IsNullOrEmpty(answer))
            {
                switch (answer)
                {
                    case "base64":
                        base64Prompt();
                        break;
                    case "encrypt":
                        EnDePrompt(true);
                        break;
                    case "decrypt":
                        EnDePrompt(false);
                        break;
                    case "exit":
                        foreach (var process in Process.GetProcessesByName("CollectionOfHandyTools"))
                        {
                            process.Kill();
                        }
                        break;
                    case "clear":
                        Console.Clear();
                        break;
                    case "sha256":
                        Console.Write("Enter the string that you wanna hash: ");
                        string rawData1 = Console.ReadLine();
                        Console.WriteLine("Hash result: " + ComputeSHA256(rawData1));
                        break;
                    case "sha1":
                        Console.Write("Enter the string that you wanna hash: ");
                        string rawData2 = Console.ReadLine();
                        Console.WriteLine("Hash result: " + SHA1(rawData2));
                        break;
                    case "sha512":
                        Console.Write("Enter the string that you wanna hash: ");
                        string rawData3 = Console.ReadLine();
                        Console.WriteLine("Hash result: " + SHA512(rawData3));
                        break;
                    case "sha384":
                        Console.Write("Enter the string that you wanna hash: ");
                        string rawData4 = Console.ReadLine();
                        Console.WriteLine("Hash result: " + SHA384(rawData4));
                        break;
                    case "md5":
                        Console.Write("Enter the string that you wanna hash: ");
                        string rawData = Console.ReadLine();
                        Console.WriteLine("Hash result: " + MD5(rawData));
                        break;
                    case "compare2hashes":
                        Console.Write("Enter the first hash: "); string firstHash = Console.ReadLine();
                        Console.Write("Enter the second hash: "); string secondHash = Console.ReadLine();
                        if (firstHash == secondHash)
                        {
                            Console.WriteLine("Hashes matched!");
                        }
                        else { Console.WriteLine("Hashes didn't match!"); }
                        break;
                }
            }
            else
            {
                Console.WriteLine("Please write what you wanna do!");
            }
        }
        static private void base64Prompt()
        {
            Console.WriteLine("Decode or encode? Type d for decode and e for encode");
            string asw = Console.ReadLine();
            switch (asw)
            {
                case "e":
                    Console.WriteLine("Enter the string that you want encoded");
                    string baseString = Console.ReadLine();
                    byte[] data = System.Text.Encoding.UTF8.GetBytes(baseString);
                    Console.WriteLine(System.Convert.ToBase64String(data));
                    break;
                case "d":
                    Console.WriteLine("Enter the string that you want decoded");
                    string encodedString = Console.ReadLine();
                    var base64EncodedBytes = System.Convert.FromBase64String(encodedString);
                    Console.WriteLine( System.Text.Encoding.UTF8.GetString(base64EncodedBytes));
                    break;
            }
        }
        static private void EnDePrompt(bool EorD)
        {
            if (EorD == true)
            {
                Console.WriteLine("Enter the string that you want encrypted");
                string text = Console.ReadLine();
                Console.WriteLine("Enter the password");
                string pwd = Console.ReadLine();
                Console.Write("Encrypted string: ");
                Console.WriteLine(Encryptv2(text, pwd));
                Console.WriteLine("Press enter to continue");
                Console.ReadLine();
                Console.Clear();
            }
            else if (EorD == false)
            {
                Console.WriteLine("Enter the string that you want decrypted");
                string text = Console.ReadLine();
                Console.WriteLine("Enter the password");
                string pwd = Console.ReadLine();
                Console.Write("Decrypted string: ");
                Console.WriteLine(Decrypt(text, pwd));
                Console.WriteLine("Press enter to continue");
                Console.ReadLine();
                Console.Clear();
            }
        }

        public static string Encryptv2(this string text, string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key must have valid value.", nameof(key));
            if (string.IsNullOrEmpty(text))
                throw new ArgumentException("The text must have valid value.", nameof(text));

            var buffer = Encoding.UTF8.GetBytes(text);
            var hash = new SHA512CryptoServiceProvider();
            var aesKey = new byte[24];
            Buffer.BlockCopy(hash.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 24);

            using (var aes = Aes.Create())
            {
                if (aes == null)
                    throw new ArgumentException("Parameter must not be null.", nameof(aes));

                aes.Key = aesKey;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(buffer))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    var result = resultStream.ToArray();
                    var combined = new byte[aes.IV.Length + result.Length];
                    Array.ConstrainedCopy(aes.IV, 0, combined, 0, aes.IV.Length);
                    Array.ConstrainedCopy(result, 0, combined, aes.IV.Length, result.Length);

                    return Convert.ToBase64String(combined);
                }
            }
        }
        public static string Decrypt(this string encryptedText, string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key must have valid value.", nameof(key));
            if (string.IsNullOrEmpty(encryptedText))
                throw new ArgumentException("The encrypted text must have valid value.", nameof(encryptedText));

            var combined = Convert.FromBase64String(encryptedText);
            var buffer = new byte[combined.Length];
            var hash = new SHA512CryptoServiceProvider();
            var aesKey = new byte[24];
            Buffer.BlockCopy(hash.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 24);

            using (var aes = Aes.Create())
            {
                if (aes == null)
                    throw new ArgumentException("Parameter must not be null.", nameof(aes));

                aes.Key = aesKey;

                var iv = new byte[aes.IV.Length];
                var ciphertext = new byte[buffer.Length - iv.Length];

                Array.ConstrainedCopy(combined, 0, iv, 0, iv.Length);
                Array.ConstrainedCopy(combined, iv.Length, ciphertext, 0, ciphertext.Length);

                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    using (var aesStream = new CryptoStream(resultStream, decryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(ciphertext))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    return Encoding.UTF8.GetString(resultStream.ToArray());
                }
            }
        }
        public static string ComputeSHA256(string text)
        {
            var result = default(string);

            using (var algo = new SHA256Managed())
            {
                result = GenerateHashString(algo, text);
            }

            return result;
        }
        public static string MD5(string text)
        {
            var result = default(string);

            using (var algo = new MD5CryptoServiceProvider())
            {
                result = GenerateHashString(algo, text);
            }

            return result;
        }
        public static string SHA512(string text)
        {
            var result = default(string);

            using (var algo = new SHA512Managed())
            {
                result = GenerateHashString(algo, text);
            }

            return result;
        }
        public static string SHA384(string text)
        {
            var result = default(string);

            using (var algo = new SHA384Managed())
            {
                result = GenerateHashString(algo, text);
            }

            return result;
        }
        public static string SHA1(string text)
        {
            var result = default(string);

            using (var algo = new SHA1Managed())
            {
                result = GenerateHashString(algo, text);
            }

            return result;
        }
        private static string GenerateHashString(HashAlgorithm algo, string text)
        {
            algo.ComputeHash(Encoding.UTF8.GetBytes(text));
            var result = algo.Hash;
            return string.Join(
                string.Empty,
                result.Select(x => x.ToString("x2")));
        }
    }
}
// Some of the code for this project is taken from Stack Overflow, and some other sites.