using System.Security.Cryptography;
using System.Text;
using System;

namespace AuthJwt
{
    public static class Settings {
        public static string Secret { get; } = "111111111111111111111111111111".Sha256();
        public static TimeSpan Expires_in { get; } = TimeSpan.FromSeconds(180);
        public static string Secret_Refresh { get; } = "22222222222222222222222222222".Sha256();

        private static string Sha256(this string input)
        {
            using (SHA256 shA256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                return Convert.ToBase64String(((HashAlgorithm)shA256).ComputeHash(bytes));
            }
        }
    }


}