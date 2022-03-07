using Mono.Security.X509;
using System;
using System.Security.Cryptography;
using System.Text;

// https://thermidor.tistory.com/431

namespace PnPeople.Security
{
    public class nPKCS12
    {
        public const string pbeWithSHAAndSEEDCBC = "1.2.410.200004.1.15";
        private byte[] _password;
        public nPKCS12()
        {
        }
        /// <summary>
        /// SEED/CBC에서 Password는 입력 문자열을 그대로 사용한다
        /// </summary>
        public string Password
        {
            set
            {
                if (!string.IsNullOrEmpty(value))
                {
                    int size = value.Length;
                    if (size > PKCS12.MaximumPasswordLength) size = PKCS12.MaximumPasswordLength;
                    _password = new byte[size];
                    Encoding.Default.GetBytes(value, 0, size, _password, 0);
                }
                else
                {
                    // no password
                    _password = null;
                }
            }
        }
        // Key, IV를 각각 64바이트로 만들어서 합친다.... 이상한 로직: 사용하면 안될 듯
        private SEED GetSymmetricAlgorithm(string algorithmOid, byte[] salt, int iterationCount)
        {
            int keyLength = 16; // 128 bits (default)
            int ivLength = 16; // 128 bits (default)
            PKCS12.DeriveBytes pd = new PKCS12.DeriveBytes();
            pd.Password = this._password;
            pd.Salt = salt;
            pd.IterationCount = iterationCount;
            switch (algorithmOid)
            {
                case pbeWithSHAAndSEEDCBC: // no unit test available
                    pd.HashName = "SHA";
                    break;
            }
            SEED seed = new SEED();
            seed.KeyBytes = pd.DeriveKey(keyLength);
            // IV required only for block ciphers (not stream ciphers)
            if (ivLength > 0)
            {
                seed.IV = pd.DeriveIV(ivLength);
                seed.ModType = SEED.MODE.AI_CBC; // CBC
            }
            return seed;
        }
        private SEED GetSymmetricAlgorithm(byte[] salt, int iterationCount)
        {
            // Rfc2898DeriveBytes 사용: 에러남
            //Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_password, salt, iterationCount); // PBKDF2
            //byte[] derivedKey = pdb.GetBytes(20);
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(_password, salt, "SHA1", iterationCount); // PBKDF1
            byte[] derivedKey = pdb.GetBytes(20);
            SEED seed = new SEED();
            seed.KeyBytes = getKey(derivedKey);
            seed.IV = getIV(derivedKey);
            seed.ModType = SEED.MODE.AI_CBC; // CBC
            return seed;
        }
        private byte[] getKey(byte[] derivedKey)
        {
            byte[] key = new byte[16];
            Buffer.BlockCopy(derivedKey, 0, key, 0, 16);
            return key;
        }
        private byte[] getIV(byte[] derivedKey)
        {
            byte[] iv = new byte[16];
            byte[] ivTemp = new byte[4];
            SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
            Buffer.BlockCopy(derivedKey, 16, ivTemp, 0, 4);
            byte[] derivedIV = sha1.ComputeHash(ivTemp);
            Buffer.BlockCopy(derivedIV, 0, iv, 0, 16);
            return iv;
        }
        public byte[] Decrypt(string algorithmOid, byte[] salt, int iterationCount, byte[] encryptedData)
        {
            if (algorithmOid != pbeWithSHAAndSEEDCBC) return null; // Only for SHA1/SEED/CBC
                                                                   // Mono DeriveBytes 사용: 에러남
                                                                   //SEED seed1 = GetSymmetricAlgorithm(algorithmOid, salt, iterationCount);
                                                                   //byte[] result1 = seed1.Decrypt(encryptedData);
            SEED seed = GetSymmetricAlgorithm(salt, iterationCount);
            byte[] result = seed.Decrypt(encryptedData);
            if (result == null)
                return null;
            // CFB 테스트
            seed.ModType = SEED.MODE.AI_CFB;
            byte[] enc = seed.Encrypt(result /*result2*/);
            byte[] dec = seed.Decrypt(enc);
            // ECB 테스트
            seed.ModType = SEED.MODE.AI_ECB;
            enc = seed.Encrypt(result /*result2*/);
            dec = seed.Decrypt(enc);
            // OFB 테스트
            seed.ModType = SEED.MODE.AI_OFB;
            enc = seed.Encrypt(result /*result2*/);
            dec = seed.Decrypt(enc);
            return result;
        }
    }
}
