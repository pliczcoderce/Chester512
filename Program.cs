using System.Text;

namespace Chester512
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var password = Chester512.GeneratePassword();
            var chesterAlgorithm = new Chester512(password);
            
            var encrypted = Convert.ToBase64String(chesterAlgorithm.Encrypt(Encoding.UTF8.GetBytes("This is just a test for testing purposes")));
            Console.WriteLine("Encrypted: " + encrypted);

            var decrypted = Encoding.UTF8.GetString(chesterAlgorithm.Decrypt(Convert.FromBase64String(encrypted)));
            Console.WriteLine("Decrypted: " + decrypted);
        }
    }
}