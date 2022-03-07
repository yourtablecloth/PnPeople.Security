using Mono.Security.X509;
using PnPeople.Security.Cryptography;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

// https://thermidor.tistory.com/431

namespace PnPeople.Security
{
    public class SHASEEDDecryptor
    {
        public const string pbeWithSHAAndSEEDCBC = "1.2.410.200004.1.15";

        public SHASEEDDecryptor()
        {
        }

        // https://stackoverflow.com/questions/818704/how-to-convert-securestring-to-system-string
        private char[] ConvertToCharArray(SecureString value)
        {
            var valuePtr = IntPtr.Zero;

            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                var recoveredArray = new char[value.Length];

                for (int i = 0; i < value.Length; i++)
                {
                    short unicodeChar = Marshal.ReadInt16(valuePtr, i * 2);
                    recoveredArray[i] = (char)unicodeChar;
                }

                return recoveredArray;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private SEED GetSymmetricAlgorithm(byte[] salt, int iterationCount, byte[] password)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, salt, "SHA1", iterationCount); // PBKDF1
            byte[] derivedKey = pdb.GetBytes(20);
            SEED seed = new SEED();
            seed.KeyBytes = GetKey(derivedKey);
            seed.IV = GetInitVector(derivedKey);
            seed.ModType = SEED.MODE.AI_CBC; // CBC
            return seed;
        }

        private byte[] GetKey(byte[] derivedKey)
        {
            byte[] key = new byte[16];
            Buffer.BlockCopy(derivedKey, 0, key, 0, 16);
            return key;
        }
        
        private byte[] GetInitVector(byte[] derivedKey)
        {
            byte[] iv = new byte[16];
            byte[] ivTemp = new byte[4];
            SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
            Buffer.BlockCopy(derivedKey, 16, ivTemp, 0, 4);
            byte[] derivedIV = sha1.ComputeHash(ivTemp);
            Buffer.BlockCopy(derivedIV, 0, iv, 0, 16);
            return iv;
        }

        public byte[] Decrypt(string algorithmOid, byte[] salt, int iterationCount, byte[] encryptedData, SecureString protectedPassword)
        {
            // Only for SHA1/SEED/CBC
            if (algorithmOid != pbeWithSHAAndSEEDCBC)
                return null;

            byte[] password = null;
            var recoveredArray = ConvertToCharArray(protectedPassword);

            if (recoveredArray.Length > 0)
            {
                int size = protectedPassword.Length;
                if (size > PKCS12.MaximumPasswordLength)
                    size = PKCS12.MaximumPasswordLength;
                password = new byte[size];
                Encoding.Default.GetBytes(recoveredArray, 0, size, password, 0);
            }
            
            for (int i = 0; i < recoveredArray.Length; i++)
                recoveredArray[i] = '\0';

            SEED seed = GetSymmetricAlgorithm(salt, iterationCount, password);
            byte[] result = seed.Decrypt(encryptedData);
            if (result == null)
                return null;

            // CFB 테스트
            seed.ModType = SEED.MODE.AI_CFB;
            byte[] enc = seed.Encrypt(result /*result2*/);
            seed.Decrypt(enc);

            // ECB 테스트
            seed.ModType = SEED.MODE.AI_ECB;
            enc = seed.Encrypt(result /*result2*/);
            seed.Decrypt(enc);

            // OFB 테스트
            seed.ModType = SEED.MODE.AI_OFB;
            enc = seed.Encrypt(result /*result2*/);
            seed.Decrypt(enc);

            return result;
        }

        [Obsolete("Please use SecureString version of this method.", false)]
        public byte[] Decrypt(string algorithmOid, byte[] salt, int iterationCount, byte[] encryptedData, char[] unprotectedPassword)
        {
            if (unprotectedPassword == null)
                return null;

            var protectedPassword = new SecureString();
            for (var i = 0; i < unprotectedPassword.Length; i++)
                protectedPassword.AppendChar(unprotectedPassword[i]);

            return Decrypt(algorithmOid, salt, iterationCount, encryptedData, protectedPassword);
        }
    }
}
