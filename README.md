# PnPeople.Security

SEED Cryptography Algorithm Library for .NET Standard 2.0+

## How to use

You can use this library to convert your SEED encrypted private key into a .NET standard RSA instance.

1. First read the .der file and the .key file respectively into a byte array.
1. Create an instance of the `System.Security.Cryptography.X509Certificates.X509Certificate2` class to read the public key data.
1. Create an instance of the `Mono.Security.Cryptography.PKCS8.EncryptedPrivateKeyInfo` class to read the private key data.
1. Create an instance of the `PnPeople.Security.SHASEEDDecryptor` class.
1. Prepare the certificate password by inputting it from the user.
1. When calling the `Decrypt` function of the SHASEEDDecryptor class, pass the secret key's algorithm, Salt, count of iterations, encrypted data, and certificate password.
1. Call the `DecodeRSA` function of the `Mono.Security.PKCS8.PrivateKeyInfo` class to change the decrypted secret key to a standard RSA provider instance in .NET.

Here is the sample application code.

```csharp
using Mono.Security.Cryptography;
using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var folder = Path.Combine(
    Environment.GetEnvironmentVariable("USERPROFILE"),
    "AppData", "LocalLow", "NPKI");

foreach (var eachProviderDirectory in Directory.GetDirectories(folder))
{
    Console.WriteLine($"[{Path.GetFileName(eachProviderDirectory)}]");

    foreach (var eachDirectory in Directory.GetDirectories(Path.Combine(eachProviderDirectory, "USER")))
    {
        Console.WriteLine($"{Path.GetFileName(eachDirectory)}");
        var certFile = Directory.GetFiles(eachDirectory, "*.der", SearchOption.TopDirectoryOnly).FirstOrDefault();

        X509Certificate cert = null;
        X509Certificate2 token = null;

        if (certFile != null && File.Exists(certFile))
        {
            cert = X509Certificate.CreateFromCertFile(certFile);
            token = new X509Certificate2(cert);

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
        Console.WriteLine("- KeyType: " + PKCS8.GetType(bytes));

        var encInfo = new PKCS8.EncryptedPrivateKeyInfo(bytes);
        Console.WriteLine("- Algorithm: " + encInfo.Algorithm);

        Console.Write("- Type private key password: ");

        SHASEEDDecryptor p12 = new SHASEEDDecryptor();
        var passwd = ReadPasswordFromConsole();
        var decrypted = p12.Decrypt(encInfo.Algorithm, encInfo.Salt, encInfo.IterationCount, encInfo.EncryptedData, passwd);

        if (decrypted != null)
        {
            var keyInfo = new PKCS8.PrivateKeyInfo(decrypted);
            var provider = PKCS8.PrivateKeyInfo.DecodeRSA(keyInfo.PrivateKey);

            var randomString = string.Concat(Enumerable.Range(1, (int)(Math.Abs(DateTime.Now.Ticks) % 9)).Select(x => Guid.NewGuid().ToString("n")));
            var buffer = Encoding.Default.GetBytes(randomString);
            var signed = provider.SignData(buffer, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            var result = provider.VerifyData(buffer, signed, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            Console.WriteLine($"- Signature Validation Result: {(result ? "Valid" : "Invalid")}");

            if (result && token != null)
            {
                var tokenWithPrivateKey = token.CopyWithPrivateKey(provider);
                var pfxData = tokenWithPrivateKey.Export(X509ContentType.Pfx, passwd);
                var directoryPath = Path.GetDirectoryName(certFile);
                var pfxPath = Path.Combine(directoryPath, "signCert.pfx");
                File.WriteAllBytes(pfxPath, pfxData);

                if (File.Exists(pfxPath))
                    Console.WriteLine($"- PFX Converted: {pfxPath}");
            }
        }
        else
        {
            Console.WriteLine($"- Cannot decrypt private key");
        }
    }
}
```

## License

This project is licensed under the MIT License.

Original Source Code Excerpted From:

- [https://thermidor.tistory.com/430](https://thermidor.tistory.com/430)
- [https://thermidor.tistory.com/431](https://thermidor.tistory.com/431)
- [Mono.Security](https://github.com/mono/mono/tree/5d2e3bc3b3c8184d35b2f7801e88d96470d367c4/mcs/class/Mono.Security)
