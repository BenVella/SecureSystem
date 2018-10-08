using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace BennetVellaSecureSoftware
{
    public class EncryptionUtility
    {
        public string FileMerge(string secretKey, string iv, string fileData)
        {
            string result = secretKey + "$KEY$" + iv + "#CONTENT#" + fileData;
            return result;
        }

        #region Asymmetric Encryption

        public AsymmetricKeys GenerateAsymmetricKeys()
        {
            //RSA DSA
            RSACryptoServiceProvider myAlg = new RSACryptoServiceProvider();
            AsymmetricKeys keys = new AsymmetricKeys()
            {
                PublicKey = myAlg.ToXmlString(false),
                PrivateKey = myAlg.ToXmlString(true)
            };

            return keys; //In Users Table store these keys separately
        }

        public string Encrypt(byte[] data, string publicKey)
        {
            string result = String.Empty;

            RSACryptoServiceProvider myAlg = new RSACryptoServiceProvider();
            myAlg.FromXmlString(publicKey);

            result = Convert.ToBase64String(myAlg.Encrypt(data, true));
            return result;
        }

        public byte[] Decrypt(string data, string privateKey)
        {
            byte[] dataByte = Convert.FromBase64String(data);

            RSACryptoServiceProvider myAlg = new RSACryptoServiceProvider();
            myAlg.FromXmlString(privateKey);

            return myAlg.Decrypt(dataByte, true);
        }

        #endregion

        #region Symmetric Encryption

        public SymmetricParameters GenerateSymmetricParameters(string password, string salt)
        {
            Rijndael myalg = Rijndael.Create();

            Rfc2898DeriveBytes mygenerator = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt));
            SymmetricParameters ps = new SymmetricParameters()
            {
                SecretKey = mygenerator.GetBytes(myalg.KeySize / 8),
                IV = mygenerator.GetBytes(myalg.BlockSize / 8)
            };
            return ps;
        }

        public string Encrypt(byte[] fileData, SymmetricParameters p)
        {
            string result = String.Empty;

            Rijndael myalg = Rijndael.Create();

            MemoryStream msOut = new MemoryStream();
            CryptoStream myEncryptingStream = new CryptoStream(msOut, myalg.CreateEncryptor(p.SecretKey, p.IV), CryptoStreamMode.Write);

            MemoryStream msIn = new MemoryStream(fileData);
            msIn.Position = 0;
            msIn.CopyTo(myEncryptingStream);
            myEncryptingStream.Flush();
            myEncryptingStream.FlushFinalBlock();

            msOut.Position = 0;

            result = Convert.ToBase64String(msOut.ToArray());

            return result;
        }

        public byte[] Decrypt(string fileData, SymmetricParameters p)
        {
            byte[] fileDataByte = Convert.FromBase64String(fileData);

            Rijndael myalg = Rijndael.Create();

            MemoryStream msOut = new MemoryStream();
            CryptoStream myEncryptingStream = new CryptoStream(msOut, myalg.CreateDecryptor(p.SecretKey, p.IV), CryptoStreamMode.Write);

            MemoryStream msIn = new MemoryStream(fileDataByte);
            msIn.Position = 0;
            msIn.CopyTo(myEncryptingStream);
            myEncryptingStream.Flush();
            myEncryptingStream.FlushFinalBlock();

            msOut.Position = 0;
            return msOut.ToArray();
        }

        #endregion

        #region Digital Signing
        public byte[] GenerateHash(byte[] fileData)
        {
            SHA256 myAlg = SHA256.Create();
            return myAlg.ComputeHash(fileData);
        }

        public string GenerateSignature(byte[] fileData, string privateKey)
        {
            RSACryptoServiceProvider myAlg = new RSACryptoServiceProvider();
            myAlg.FromXmlString(privateKey);

            byte[] signature = myAlg.SignHash(GenerateHash(fileData), "SHA256");
            return Convert.ToBase64String(signature);
        }

        public bool VerifySignature(byte[] fileData, string publicKey, string signature)
        {
            RSACryptoServiceProvider myAlg = new RSACryptoServiceProvider();
            myAlg.FromXmlString(publicKey);

            bool flag = myAlg.VerifyHash(GenerateHash(fileData), "SHA256", Convert.FromBase64String(signature));
            return flag;
        }

        public string ReadFromFile(string path)
        {
            string iFile = System.IO.File.ReadAllText(path);
            return iFile;
        }

        public void WriteToFile(string path, string file)
        {
            System.IO.File.WriteAllText(path, file);
        }
        #endregion
    }

    #region Encryption Datatypes
    public class SymmetricParameters
    {
        public byte[] SecretKey { get; set; }
        public byte[] IV { get; set; }
    }

    public class AsymmetricKeys
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
    #endregion
}