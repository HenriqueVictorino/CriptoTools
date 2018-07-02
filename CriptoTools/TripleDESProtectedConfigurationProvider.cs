using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace CriptoTools
{
    public class TripleDESProtectedConfigurationProvider : ProtectedConfigurationProvider
    {
        private TripleDESCryptoServiceProvider Cripto = new TripleDESCryptoServiceProvider();
        private string key = "Sgo0k8dv112TCU0BiMNOo0tfR5AYmXeC";
        private string IV = "mmVbNIIj8k4=";

        public TripleDESProtectedConfigurationProvider()
        {
            Cripto.Key = Convert.FromBase64String(key);
            Cripto.IV = Convert.FromBase64String(IV);

            Cripto.Mode = CipherMode.ECB;
            Cripto.Padding = PaddingMode.PKCS7;
        }


        public override XmlNode Encrypt(XmlNode node)
        {

            string encryptedData = EncryptString(node.OuterXml);

            XmlDocument xmlDoc = new XmlDocument
            {
                PreserveWhitespace = true
            };

            xmlDoc.LoadXml("<EncryptedData>" + encryptedData + "</EncryptedData>");
            return xmlDoc.DocumentElement;
        }


        public override XmlNode Decrypt(XmlNode encryptedNode)
        {
            string decryptedData = DecryptString(encryptedNode.InnerText);

            XmlDocument xmlDoc = new XmlDocument
            {
                PreserveWhitespace = true
            };

            xmlDoc.LoadXml(decryptedData);

            return xmlDoc.DocumentElement;
        }

        private string EncryptString(string encryptValue)
        {

            byte[] valBytes = Encoding.Unicode.GetBytes(encryptValue);

            ICryptoTransform transform = Cripto.CreateEncryptor();

            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write);
            cs.Write(valBytes, 0, valBytes.Length);
            cs.FlushFinalBlock();

            byte[] returnBytes = ms.ToArray();
            cs.Close();

            return Convert.ToBase64String(returnBytes);
        }

        private string DecryptString(string encryptedValue)
        {
            byte[] valBytes = Convert.FromBase64String(encryptedValue);

            ICryptoTransform transform = Cripto.CreateDecryptor();

            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write);
            cs.Write(valBytes, 0, valBytes.Length);
            cs.FlushFinalBlock();
            byte[] returnBytes = ms.ToArray();
            cs.Close();

            return Encoding.Unicode.GetString(returnBytes);
        }

    }
}
