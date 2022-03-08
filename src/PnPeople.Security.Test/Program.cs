using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PnPeople.Security.Test
{
    internal static class Program
    {
        private static void Main()
        {
            var folder = Path.Combine(
                Environment.GetEnvironmentVariable("USERPROFILE"),
                "AppData", "LocalLow", "NPKI");

            // 실제 개인 인증서 접근 부분
            foreach (var eachProviderDirectory in Directory.GetDirectories(folder))
            {
                Console.WriteLine($"[{Path.GetFileName(eachProviderDirectory)}]");

                foreach (var eachDirectory in Directory.GetDirectories(Path.Combine(eachProviderDirectory, "USER")))
                {
                    Console.WriteLine($"{Path.GetFileName(eachDirectory)}");
                    var certFile = Directory.GetFiles(eachDirectory, "*.der", SearchOption.TopDirectoryOnly).FirstOrDefault();

                    X509Certificate2 token = null;

                    if (certFile != null && File.Exists(certFile))
                    {
                        token = new X509Certificate2(X509Certificate.CreateFromCertFile(certFile));

                        Console.WriteLine("- IssuerName: " + token.Issuer);
                        Console.WriteLine("- KeyAlgorithm: " + token.GetKeyAlgorithm());
                        Console.WriteLine("- KeyAlgorithmParameters: " + token.GetKeyAlgorithmParametersString());
                        Console.WriteLine("- Name: " + token.Subject);
                        Console.WriteLine("- PublicKey: " + token.GetPublicKeyString());
                        Console.WriteLine("- SerialNumber: " + token.GetSerialNumberString());
                        Console.WriteLine("- HasPrivateKey: " + token.HasPrivateKey);

                        var currentDateTime = DateTime.Now;
                        if (currentDateTime <= token.NotBefore)
                        {
                            Console.WriteLine("- Certificate is not valid yet.");
                            continue;
                        }
                        else if (token.NotAfter <= currentDateTime)
                        {
                            Console.WriteLine("- Certificate has expiered.");
                            continue;
                        }
                    }

                    var keyFile = Directory.GetFiles(eachDirectory, "*.key", SearchOption.TopDirectoryOnly).FirstOrDefault();

                    if (keyFile == null || !File.Exists(keyFile))
                        continue;

                    var bytes = File.ReadAllBytes(keyFile);
                    var privKeyInfo = CertPrivateKeyHelper.GetPrivateKeyInfo(bytes);
                    Console.WriteLine("- KeyType: " + privKeyInfo.KeyType);
                    Console.WriteLine("- Algorithm: " + privKeyInfo.Algorithm);

                    Console.Write("- Type private key password: ");
                    var passwd = ReadPasswordFromConsole();

                    var copiedPassword = CertPrivateKeyHelper.CopyFromSecureString(passwd);
                    var decryptor = CertPrivateKeyHelper.GetPrivateKeyDecryptor(privKeyInfo);

                    if (decryptor == null)
                    {
                        Console.WriteLine("- Unsupported algorithm found.");
                        continue;
                    }

                    var provider = decryptor.Invoke(privKeyInfo, copiedPassword);

                    if (provider != null)
                    {
                        // 개인키를 이용한 전자서명 테스트
                        var randomString = string.Concat(Enumerable.Range(1, (int)(Math.Abs(DateTime.Now.Ticks) % 9)).Select(x => Guid.NewGuid().ToString("n")));
                        var buffer = Encoding.Default.GetBytes(randomString);
                        var signed = provider.SignData(buffer, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                        var result = provider.VerifyData(buffer, signed, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                        Console.WriteLine($"- Signature Validation Result: {(result ? "Valid" : "Invalid")}");

                        if (result && token != null)
                        {
                            var tokenWithPrivateKey = token.CopyWithPrivateKey(provider);
                            var directoryPath = Path.GetDirectoryName(certFile);

                            var pfxData = tokenWithPrivateKey.Export(X509ContentType.Pfx, passwd);
                            var pfxPath = Path.Combine(directoryPath, "signCertNew.pfx");
                            File.WriteAllBytes(pfxPath, pfxData);

                            if (File.Exists(pfxPath))
                                Console.WriteLine($"- PFX Converted: {pfxPath}");

                            // PFX를 다시 DER/KEY로 분리 (단, SEED 암호화는 사용하지 않음)
                            tokenWithPrivateKey = new X509Certificate2(File.ReadAllBytes(pfxPath), passwd, X509KeyStorageFlags.Exportable);

                            var certData = tokenWithPrivateKey.Export(X509ContentType.Cert);
                            var certPath = Path.Combine(directoryPath, "signCertNew.der");
                            File.WriteAllBytes(certPath, certData);

                            if (File.Exists(certPath))
                                Console.WriteLine($"- Certificate converted: {certPath}");

                            // https://www.rootca.or.kr/kcac/down/Guide/Implementation_Guideline_for_Safe_Usage_of_Accredited_Certificate_using_bio_information_in_Smart_phone.pdf
                            // 위 문서의 '2.2 공인인증서 전자서명생성정보 저장 방안' 내용에 따르면 IterationCount는 2048로 약속된 것 같다.
                            var keyData = tokenWithPrivateKey.GetRSAPrivateKey().ExportEncryptedPkcs8PrivateKey(
                                copiedPassword,
                                new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048));

                            var keyPath = Path.Combine(directoryPath, "signPriNew.key");
                            File.WriteAllBytes(keyPath, keyData);

                            if (File.Exists(keyPath))
                                Console.WriteLine($"- Private key converted: {keyPath}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"- Cannot decrypt private key");
                    }
                }
            }
        }

        // https://stackoverflow.com/questions/3404421/password-masking-console-application
        private static SecureString ReadPasswordFromConsole()
        {
            var pass = new SecureString();

            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass.RemoveAt(pass.Length - 1);
                    //pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass.AppendChar(keyInfo.KeyChar);
                    //pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            Console.WriteLine();
            return pass;
        }
    }
}
