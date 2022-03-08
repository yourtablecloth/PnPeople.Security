using Mono.Security.Cryptography;
using Mono.Security.X509;
using PnPeople.Security.Models;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace PnPeople.Security
{
    public static class CertPrivateKeyHelper
    {
        private static readonly string[] CompatibleAlgorithms = new string[]
        {
            PKCS12.pbeWithSHAAnd128BitRC4,
            PKCS12.pbeWithSHAAnd40BitRC4,
            PKCS12.pbeWithSHAAnd3KeyTripleDESCBC,
            PKCS12.pbeWithSHAAnd2KeyTripleDESCBC,
            PKCS12.pbeWithSHAAnd128BitRC2CBC,
            PKCS12.pbeWithSHAAnd40BitRC2CBC,
        };

        public static CertPrivateKeyInfo GetPrivateKeyInfo(byte[] privateKeyContents)
        {
            if (privateKeyContents == null || privateKeyContents.Length < 1)
                return null;

            var encInfo = new PKCS8.EncryptedPrivateKeyInfo(privateKeyContents);

            if (encInfo == null)
                return null;

            return new CertPrivateKeyInfo()
            {
                KeyType = (CertPrivateKeyType)PKCS8.GetType(privateKeyContents),
                Algorithm = encInfo.Algorithm,
                EncryptedData = encInfo.EncryptedData,
                Salt = encInfo.Salt,
                IterationCount = encInfo.IterationCount,
            };
        }

        public static Func<CertPrivateKeyInfo, char[], RSA> GetPrivateKeyDecryptor(CertPrivateKeyInfo privateKeyInfo)
        {
            if (privateKeyInfo == null)
                return null;

            if (string.Equals(privateKeyInfo.Algorithm, SHASEEDDecryptor.pbeWithSHAAndSEEDCBC, StringComparison.Ordinal))
            {
                return (privKeyInfo, password) =>
                {
                    SHASEEDDecryptor p12 = new SHASEEDDecryptor();
                    var decrypted = p12.Decrypt(privKeyInfo.Algorithm, privKeyInfo.Salt, privKeyInfo.IterationCount, privKeyInfo.EncryptedData, password);

                    if (decrypted == null)
                        return null;

                    var keyInfo = new PKCS8.PrivateKeyInfo(decrypted);
                    return PKCS8.PrivateKeyInfo.DecodeRSA(keyInfo.PrivateKey);
                };
            }
            else if (CompatibleAlgorithms.Contains(privateKeyInfo.Algorithm, StringComparer.Ordinal))
            {
                return (privKeyInfo, password) =>
                {
                    var p12 = new PKCS12();
                    p12.Password = new string(password);
                    var decrypted = p12.Decrypt(privKeyInfo.Algorithm, privKeyInfo.Salt, privKeyInfo.IterationCount, privKeyInfo.EncryptedData);

                    if (decrypted == null)
                        return null;

                    var keyInfo = new PKCS8.PrivateKeyInfo(decrypted);
                    return PKCS8.PrivateKeyInfo.DecodeRSA(keyInfo.PrivateKey);
                };
            }
            else
                return null;
        }

        public static char[] CopyFromSecureString(SecureString s)
        {
            var ptr = IntPtr.Zero;

            try
            {
                ptr = Marshal.SecureStringToBSTR(s);
                return Marshal.PtrToStringBSTR(ptr).ToCharArray();
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(ptr);
            }
        }
    }
}
