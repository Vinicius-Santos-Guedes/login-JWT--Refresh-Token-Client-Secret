using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using PemUtils;

namespace RSALib
{
    public class RSAHandler
    {
        private int _keySize = 1024;

        public RSAHandler()
        {
            _keySize = 2048;
        }
        public RSAHandler(int keySize)
        {
            _keySize = keySize;
        }

        private RSA GetRSACryptoProvider(int keySize)
        {
            try
            {
                var rsa = RSA.Create();
                rsa.KeySize = keySize;
                return rsa;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in GetRSACryptoProvider(): {ex}");
                return null;
            }
        }

        private RSA GetRSACryptoProvider(int keySize, string keyFileName = null)
        {
            var rsa = RSA.Create();

            try
            {
                if (string.IsNullOrEmpty(keyFileName))
                {
                    rsa.KeySize = keySize;
                }
                else
                {
                    using (var privateKey = File.OpenRead(keyFileName))
                    {
                        using (var pem = new PemReader(privateKey))
                        {
                            var rsaParameters = pem.ReadRsaKey();
                            rsa.ImportParameters(rsaParameters);
                        }
                    }
                }
                return rsa;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in GetRSACryptoProvider(): {ex}");
                return null;
            }
        }

        public void CreateKeys(string publicKeyPath, string privateKeyPath)
        {
            using (RSA rsa = GetRSACryptoProvider(_keySize))
            {
                // Export the RSA public key
                using (var fs = File.Create(publicKeyPath))
                {
                    using (var pem = new PemWriter(fs))
                    {
                        pem.WritePublicKey(rsa);
                    }
                }

                // Export the RSA private key (put this somewhere safe!)
                using (var fs = File.Create(privateKeyPath))
                {
                    using (var pem = new PemWriter(fs))
                    {
                        pem.WritePrivateKey(rsa);
                    }
                }
            }
        }

        public string Encrypt(string content, string publicKeyPath)
        {
            string plainText = string.Empty;
            // cria RSAProvider com a chave publica
            using (RSA rsa = GetRSACryptoProvider(_keySize, publicKeyPath))
            {
                // pega bytes da string que sera criptografada
                byte[] plainTextBytes = Encoding.Unicode.GetBytes(content);
                // criptografa os bytes da string
                byte[] cipherTextBytes = rsa.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);
                // converte os bytes criptografados em uma string
                plainText = Convert.ToBase64String(cipherTextBytes);
            }
            return plainText;
        }

        public string Decrypt(string cipherText, string privateKeyPath)
        {
            string plainText = string.Empty;
            // cria RSAProvider com a chave privada
            using (RSA rsa = GetRSACryptoProvider(_keySize, privateKeyPath))
            {
                // pega bytes do texto criptografado
                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
                // descriptografa os bytes
                byte[] plainTextBytes = rsa.Decrypt(cipherTextBytes, RSAEncryptionPadding.Pkcs1);
                // converte os bytes descriptografados em uma string
                plainText = Encoding.Unicode.GetString(plainTextBytes);
            }
            return plainText;
        }

        public bool IsRSAToken(string token, string rsaPrivateKeyPath, string[] validKeys)
        {
            bool valid = false;
            try
            {
                string desCrypt = Decrypt(token, rsaPrivateKeyPath);
                foreach (string key in validKeys)
                {
                    if (desCrypt == key)
                    {
                        valid = true;
                        break;
                    }
                }
            }
            catch
            {
                valid = false;
            }
            return valid;
        }

    }
}
