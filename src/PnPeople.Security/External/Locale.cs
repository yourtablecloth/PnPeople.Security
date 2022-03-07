namespace Mono
{
    internal static class Locale
    {
        public static string GetText(string text)
        {
            return text;
        }

        public static string GetText(string text, params object[] args)
        {
            return string.Format(text, args);
        }
    }
}
