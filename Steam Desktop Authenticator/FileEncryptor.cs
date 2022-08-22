using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Steam_Desktop_Authenticator
{
    /// <summary>
    /// This class provides the controls that will encrypt and decrypt the *.maFile files
    /// 
    /// Passwords entered will be passed into PBKDF2 (RFC2898) with a salt derived from SHA256 hashing the password.
    /// The generated key will then be passed into AES which will encrypt the data
    /// in cypher block chaining (CBC) mode, and then write encrypted data onto the disk.
    /// </summary>
    public static class FileEncryptor
    {
        private const int PBKDF2_ITERATIONS_KEY = 13337;
        private const int PBKDF2_ITERATIONS_IV = 13337;
        private const int KEY_SIZE_BYTES = 32;
        private const int IV_SIZE_BYTES = 16;

        private static byte[] GetEncryptionKey(string password)
        {
            using Rfc2898DeriveBytes pbkdf2 = new(password, DeriveSalt(password), PBKDF2_ITERATIONS_KEY, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(KEY_SIZE_BYTES);
        }
        private static byte[] GetInitializationVector(string password)
        {
            using Rfc2898DeriveBytes pbkdf2 = new(password, DeriveSalt(password), PBKDF2_ITERATIONS_IV, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(IV_SIZE_BYTES);
        }
        private static byte[] DeriveSalt(string password)
        {
            using SHA256 hasher = SHA256.Create();
            byte[] salt = hasher.ComputeHash(Encoding.UTF8.GetBytes(password));
            return salt;
        }
        public static string DecryptData(string password, string encryptedData)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is empty");
            }
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentException("Encrypted data is empty");
            }

            byte[] cipherText = Convert.FromBase64String(encryptedData);
            byte[] key = GetEncryptionKey(password);
            byte[] iv = GetInitializationVector(password);
            string plaintext = null;

            using Aes aes = Aes.Create("AesManaged");
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            var decryptor = aes.CreateDecryptor();

            //wrap in a try since a bad password yields a bad key, which would throw an exception on decrypt
            try
            {
                using MemoryStream msDecrypt = new(cipherText);
                using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
                using StreamReader srDecrypt = new(csDecrypt);
                plaintext = srDecrypt.ReadToEnd();
            }
            catch (CryptographicException)
            {
                plaintext = null;
            }

            return plaintext;
        }
        public static string EncryptData(string password, string plaintext)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is empty");
            }
            if (string.IsNullOrEmpty(plaintext))
            {
                throw new ArgumentException("Plaintext data is empty");
            }
            byte[] key = GetEncryptionKey(password);
            byte[] iv = GetInitializationVector(password);
            byte[] ciphertext;

            using Aes aes = Aes.Create("AesManaged");
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            var encryptor = aes.CreateEncryptor();

            using MemoryStream msEncrypt = new();
            using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (StreamWriter swEncypt = new(csEncrypt))
            {
                swEncypt.Write(plaintext);
            }
            ciphertext = msEncrypt.ToArray();

            return Convert.ToBase64String(ciphertext);
        }
    }
}
