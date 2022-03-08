namespace PnPeople.Security.Models
{
    public sealed class CertPrivateKeyInfo
    {
        public CertPrivateKeyType KeyType { get; internal set; }

        public string Algorithm { get; internal set; }

        public byte[] Salt { get; internal set; }

        public int IterationCount { get; internal set; }

        public byte[] EncryptedData { get; internal set; }
    }
}
