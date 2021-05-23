using Microsoft.AspNetCore.Hosting;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RSALib
{
    /// <summary>
    /// Classe para criptografia e descriptografia RSA
    /// </summary>
    public static class RSAPFX
    {
        public static string EncryptUsingCertificate(string data, string pathstring)//pem
        {
            try
            {
                byte[] byteData = Encoding.UTF8.GetBytes(data);
                //    string path = Path.Combine(_hostEnvironment.WebRootPath, @$"{pathstring}");
                var collection = new X509Certificate2Collection();
                collection.Import(pathstring);
                var certificate = collection[0];
                var output = "";
                using (System.Security.Cryptography.RSA csp = (System.Security.Cryptography.RSA)certificate.PublicKey.Key)
                {
                    byte[] bytesEncrypted = csp.Encrypt(byteData, RSAEncryptionPadding.OaepSHA1);
                    output = Convert.ToBase64String(bytesEncrypted);
                }
                return output;
            }
            catch (Exception ex)
            {
                return "";
            }
        }


        public static bool DecryptUsingCertificate(string data, string pathstring, string validKeys)//pfx
        {
            try
            {
                byte[] byteData = Convert.FromBase64String(data);
                // string path = Path.Combine(_hostEnvironment.WebRootPath, pathstring);
                var Password = ""; //Note This Password is That Password That We Have Put On Generate Keys  
                var collection = new X509Certificate2Collection();
                collection.Import(System.IO.File.ReadAllBytes(pathstring), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                X509Certificate2 certificate = new X509Certificate2();
                certificate = collection[0];
                foreach (var cert in collection)
                {
                    if (cert.FriendlyName.Contains("my certificate"))
                    {
                        certificate = cert;
                    }
                }
                if (certificate.HasPrivateKey)
                {
                    System.Security.Cryptography.RSA csp = (System.Security.Cryptography.RSA)certificate.PrivateKey;
                    var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                    var keys = Encoding.UTF8.GetString(csp.Decrypt(byteData, RSAEncryptionPadding.OaepSHA1));
                    if (keys == validKeys) return true;
                }
            }
            catch (Exception ex) { }
            return false;
        }

    }
}