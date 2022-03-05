using System;

namespace PnPeople.Security
{
    internal static class CryptUtil
    {
        public static string GetHexFromByte(byte[] blob)
        {
            return Convert.ToBase64String(blob);
        }

        public static byte[] GetHexArray(string hexString)
        {
            return Convert.FromBase64String(hexString);
        }
    }
}