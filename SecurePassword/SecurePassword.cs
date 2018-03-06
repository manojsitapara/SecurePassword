using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Task = Microsoft.Build.Utilities.Task;
using System.Security.Cryptography;
using System.IO;

namespace SecurePassword
{
    public class SecurePassword : Task
    {
        [Required]
        public string InputString { get; set; }
        [Required]
        public bool IsEncrypt { get; set; }

        [Output]
        public string OutputString { get; set; }
        [Output]
        public string ErrorMessage { get; set; }

        public override bool Execute()
        {
            try
            {
                int keySize = 256;

                if (IsEncrypt)
                {
                    OutputString = Encrypt(InputString, "V1N0ZmwwUW5HMWNUYitTb3VFcXlnQT09LHA3ekpzaFc2M1VJdUdzT2NYcWlvYUFOOXpwNVlKWFB1WFFLcGNNaUJNVVk9" , keySize);
                }
                else
                {
                    OutputString = Decrypt(InputString, "V1N0ZmwwUW5HMWNUYitTb3VFcXlnQT09LHA3ekpzaFc2M1VJdUdzT2NYcWlvYUFOOXpwNVlKWFB1WFFLcGNNaUJNVVk9", keySize);
                }


                return true;
            }
            catch(Exception ex)
            {
                ErrorMessage = ex.Message;
                return false;
            }
            
        }

        #region Encryption
        /// <summary>
        /// Generate a private key
        /// </summary>
        private static string GenerateKey(int iKeySize)
        {
            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.KeySize = iKeySize;
            aesEncryption.BlockSize = 128;
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.GenerateIV();
            string ivStr = Convert.ToBase64String(aesEncryption.IV);
            aesEncryption.GenerateKey();
            string keyStr = Convert.ToBase64String(aesEncryption.Key);
            string completeKey = ivStr + "," + keyStr;

            return Convert.ToBase64String(ASCIIEncoding.UTF8.GetBytes(completeKey));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        private static string Encrypt(string iPlainStr, string iCompleteEncodedKey, int iKeySize)
        {
            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.KeySize = iKeySize;
            aesEncryption.BlockSize = 128;
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.IV = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[0]);
            aesEncryption.Key = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[1]);
            byte[] plainText = ASCIIEncoding.UTF8.GetBytes(iPlainStr);
            ICryptoTransform crypto = aesEncryption.CreateEncryptor();
            byte[] cipherText = crypto.TransformFinalBlock(plainText, 0, plainText.Length);
            return Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        private static string Decrypt(string iEncryptedText, string iCompleteEncodedKey, int iKeySize)
        {
            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.KeySize = iKeySize;
            aesEncryption.BlockSize = 128;
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.IV = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[0]);
            aesEncryption.Key = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[1]);
            ICryptoTransform decrypto = aesEncryption.CreateDecryptor();
            byte[] encryptedBytes = Convert.FromBase64CharArray(iEncryptedText.ToCharArray(), 0, iEncryptedText.Length);
            return ASCIIEncoding.UTF8.GetString(decrypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length));
        }
        #endregion
    }

}
