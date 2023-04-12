using System;
using System.IO;
using System.Security;
using System.Text;

namespace Chester512
{
    internal class Program
    {
        static void Main()
        {
            try
            {
                Console.Title = "Chester Algorithm";
                
                Console.Write("Input text: ");
                var inputText = Console.ReadLine()!;

                Console.Write("Password: ");
                using var securePassword = new SecureString();
                ConsoleKeyInfo key;
                do
                {
                    key = Console.ReadKey(true);
                    if (key.Key != ConsoleKey.Enter)
                    {
                        securePassword.AppendChar(key.KeyChar);
                        Console.Write("*");
                    }
                } while (key.Key != ConsoleKey.Enter);
                
                var chesterAlgorithm = new Chester512(securePassword);
                var encryptedData = chesterAlgorithm.Encrypt(Encoding.UTF8.GetBytes(inputText));
                var encryptedText = Convert.ToBase64String(encryptedData);
                
                Console.WriteLine();
                Console.WriteLine("Encrypted text: " + encryptedText);

                var decryptedData = chesterAlgorithm.Decrypt(encryptedData);
                Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decryptedData));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Console.WriteLine();
                Main();
            }
        }
    }
}
