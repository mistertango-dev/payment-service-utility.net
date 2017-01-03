using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class ProtectionMT
{
    public string OpenSSLDecrypt(string encrypted, string passphrase)
    {
        byte[] encryptedBytesWithSalt = Convert.FromBase64String(encrypted);
        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[encryptedBytesWithSalt.Length - iv.Length];
        Buffer.BlockCopy(encryptedBytesWithSalt, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(encryptedBytesWithSalt, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

        passphrase = passphrase.PadRight(32, '\0');

        byte[] key = Encoding.ASCII.GetBytes(passphrase);

        return DecryptStringFromBytesAes(encryptedBytes, key, iv);
    }


    static string DecryptStringFromBytesAes(byte[] cipherText, byte[] key, byte[] iv)
    {
        // Check arguments.
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException("key");
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException("iv");

        // Declare the RijndaelManaged object
        // used to decrypt the data.
        RijndaelManaged aesAlg = null;

        // Declare the string used to hold
        // the decrypted text.
        string plaintext;

        try
        {
            // Create a RijndaelManaged object
            // with the specified key and IV.
            aesAlg = new RijndaelManaged { Mode = CipherMode.CBC, KeySize = 128, BlockSize = 128, Key = key, IV = iv, Padding = PaddingMode.Zeros };


            // Create a decrytor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                        srDecrypt.Close();
                    }
                }
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        return plaintext;
    }
}
