using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mono.Security.Cryptography;

// https://thermidor.tistory.com/431

namespace PnPeople.Security
{
    /// <summary>
    /// test에 대한 요약 설명입니다.
    /// </summary>
    class CertTest
    {
        /// <summary>
        /// 공인인증서 읽기
        /// </summary>
        [STAThread]
        static void Main()
        {
            string folder = Environment.GetEnvironmentVariable("ProgramFiles") + "\\NPKI\\yessign"; // XP, yessign 인증서인 경우
            if (Environment.OSVersion.Version.Major >= 6)
                folder = Environment.GetEnvironmentVariable("LOCALAPPDATA") + "Low\\NPKI\\KICA"; // > Windows 7, KICA 인증서인 경우
                                                                                                 // 인증기관 인증서(공개키) --> 이 부분은 그냥 아무 의미 없는 테스트...
                                                                                                 // 자신의 PC에 있는 인증기관 인증서 파일명을 쓰면 된다
            string certFile = folder + "\\B909F2B621489A2ABA025980862793166A77F559_10081.der";
            X509Certificate cert = X509Certificate.CreateFromCertFile(certFile);
            X509Certificate2 token = new X509Certificate2(cert);
            Console.WriteLine("IssuerName: " + token.Issuer);
            Console.WriteLine("KeyAlgorithm: " + token.GetKeyAlgorithm());
            Console.WriteLine("KeyAlgorithmParameters: " + token.GetKeyAlgorithmParametersString());
            Console.WriteLine("Name: " + token.Subject);
            Console.WriteLine("PublicKey: " + token.GetPublicKeyString());
            Console.WriteLine("SerialNumber: " + token.GetSerialNumberString());
            // 실제 개인 인증서 접근 부분
            DirectoryInfo keyDir = new DirectoryInfo(folder + "\\USER");
            byte[] bytes = null;
            foreach (DirectoryInfo dir in keyDir.GetDirectories())
            {
                FileInfo[] files = dir.GetFiles("s*.key"); // 개인키 파일
                FileStream stream = files[0].OpenRead();
                stream.Position = 0;
                bytes = new byte[stream.Length];
                stream.Read(bytes, 0, (int)stream.Length);
                stream.Close();
            }
            Console.WriteLine("KeyType: " + PKCS8.GetType(bytes));
            PKCS8.EncryptedPrivateKeyInfo encInfo = new PKCS8.EncryptedPrivateKeyInfo(bytes);
            Console.WriteLine("Algorithm: " + encInfo.Algorithm);
            nPKCS12 p12 = new nPKCS12();
            p12.Password = "********"; // 실제 개인키 암호
            byte[] decrypted = p12.Decrypt(encInfo.Algorithm, encInfo.Salt, encInfo.IterationCount, encInfo.EncryptedData);
            if (decrypted != null)
            {
                PKCS8.PrivateKeyInfo keyInfo = new PKCS8.PrivateKeyInfo(decrypted);
                RSA rsa2 = PKCS8.PrivateKeyInfo.DecodeRSA(keyInfo.PrivateKey);
                RSACryptoServiceProvider provider = (RSACryptoServiceProvider)rsa2;
                // 개인키를 이용한 전자서명 테스트
                byte[] buffer = Encoding.Default.GetBytes("1234567890");
                byte[] signed = provider.SignData(buffer, "SHA1");
                //provider.VerifyData(signed, "SHA1", signed);
            }
        }
    }
}
