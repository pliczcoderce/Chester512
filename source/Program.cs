using System;
using System.IO;
using System.Text;

namespace Chester512
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var password = Chester512.GeneratePassword();
            var chesterAlgorithm = new Chester512(password);

            var inputText = "This example demonstrates the encryption and decryption of text using the Chester512 algorithm.";

            var inputData = Encoding.UTF8.GetBytes(inputText);
            var encryptedData = chesterAlgorithm.Encrypt(inputData);
            var encryptedText = Convert.ToBase64String(encryptedData);
            Console.WriteLine("Encrypted text: " + encryptedText);

            var decryptedData = chesterAlgorithm.Decrypt(encryptedData);
            var decryptedText = Encoding.UTF8.GetString(decryptedData);
            Console.WriteLine("Decrypted text: " + decryptedText);
        }
    }
}
