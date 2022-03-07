using Mono.Security.Cryptography;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PnPeople.Security.Test
{
    internal static class Program
    {
        private static void Main()
        {
            string folder = Path.Combine(
                Environment.GetEnvironmentVariable("USERPROFILE"),
                "AppData", "LocalLow", "NPKI", "yessign");

            // 실제 개인 인증서 접근 부분
            foreach (var eachDirectory in Directory.GetDirectories(Path.Combine(folder, "USER")))
            {
                Console.WriteLine($"{Path.GetFileName(eachDirectory)}");
                var certFile = Directory.GetFiles(eachDirectory, "*.der", SearchOption.TopDirectoryOnly).FirstOrDefault();

                if (certFile != null && File.Exists(certFile))
                {
                    X509Certificate cert = X509Certificate.CreateFromCertFile(certFile);
                    X509Certificate2 token = new X509Certificate2(cert);

                    Console.WriteLine("- IssuerName: " + token.Issuer);
                    Console.WriteLine("- KeyAlgorithm: " + token.GetKeyAlgorithm());
                    Console.WriteLine("- KeyAlgorithmParameters: " + token.GetKeyAlgorithmParametersString());
                    Console.WriteLine("- Name: " + token.Subject);
                    Console.WriteLine("- PublicKey: " + token.GetPublicKeyString());
                    Console.WriteLine("- SerialNumber: " + token.GetSerialNumberString());
                }

                var keyFile = Directory.GetFiles(eachDirectory, "*.key", SearchOption.TopDirectoryOnly).FirstOrDefault();

                if (keyFile == null || !File.Exists(keyFile))
                    continue;

                byte[] bytes = File.ReadAllBytes(keyFile);
                Console.WriteLine("- KeyType: " + PKCS8.GetType(bytes));

                PKCS8.EncryptedPrivateKeyInfo encInfo = new PKCS8.EncryptedPrivateKeyInfo(bytes);
                Console.WriteLine("- Algorithm: " + encInfo.Algorithm);

                Console.Write("- Type private key password: ");

                nPKCS12 p12 = new nPKCS12();
                p12.Password = ReadPasswordFromConsole(); // 실제 개인키 암호
                byte[] decrypted = p12.Decrypt(encInfo.Algorithm, encInfo.Salt, encInfo.IterationCount, encInfo.EncryptedData);

                if (decrypted != null)
                {
                    PKCS8.PrivateKeyInfo keyInfo = new PKCS8.PrivateKeyInfo(decrypted);
                    RSA provider = PKCS8.PrivateKeyInfo.DecodeRSA(keyInfo.PrivateKey);

                    // 개인키를 이용한 전자서명 테스트
                    byte[] buffer = Encoding.Default.GetBytes("1234567890");
                    byte[] signed = provider.SignData(buffer, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                    var result = provider.VerifyData(buffer, signed, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                    Console.WriteLine($"- Signature Validation Result: {(result ? "Valid" : "Invalid")}");
                }
            }
        }

        // https://stackoverflow.com/questions/3404421/password-masking-console-application
        private static string ReadPasswordFromConsole()
        {
            var pass = string.Empty;

            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            Console.WriteLine();
            return pass;
        }
    }
}
