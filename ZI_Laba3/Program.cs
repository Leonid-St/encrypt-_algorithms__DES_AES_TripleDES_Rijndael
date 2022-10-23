using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ZI_Laba3
{
    class ExecuteCryptography
    {
        // Создаем кодировщик символов
        private UTF7Encoding utf7 = new UTF7Encoding();

        // Объявляем ссылки на шифровальщик,
        // на массивы Key и IV (Initialization Vector) 
        private SymmetricAlgorithm codec;
        private byte[] key;
        private byte[] initVector;// IV

        // Конструктор
        public ExecuteCryptography(SymmetricAlgorithm codec)
        {
            this.key = codec.Key;
            this.initVector = codec.IV;
            this.codec = codec;
        }

        public string Encrypt(string text)
        {
            byte[] input = utf7.GetBytes(text);
            byte[] output = Transform(input,
                            codec.CreateEncryptor(key, initVector));
            return Convert.ToBase64String(output);
        }
        public string Decrypt(string text)
        {
            byte[] input = Convert.FromBase64String(text);
            byte[] output = Transform(input,
                            codec.CreateDecryptor(key, initVector));
            return utf7.GetString(output);
        }

        private byte[] Transform(byte[] input, ICryptoTransform cryptoTransform)
        {
            // Создаем потоки
            MemoryStream memoryStream = // Поток памяти
                new MemoryStream();
            CryptoStream cryptoStream = // Шифропоток-оболочка
                new CryptoStream(memoryStream,
                    cryptoTransform, CryptoStreamMode.Write);

            // Кодируем в поток памяти через шифропоток
            cryptoStream.Write(input, 0, input.Length);
            cryptoStream.FlushFinalBlock();

            // Преобразуем заполненный поток памяти в массив байтов
            byte[] result = memoryStream.ToArray();

            // Останавливаем потоки
            memoryStream.Close();
            cryptoStream.Close();

            // Возвращаем кодированное/раскодированное
            return result;
        }

        // Перегруженные методы
        public byte[] Encrypt(byte[] input)
        {
            return Transform(input,
                   codec.CreateEncryptor(key, initVector));
        }
        public byte[] Decrypt(byte[] input)
        {
            return Transform(input,
                   codec.CreateDecryptor(key, initVector));
        }
    }
    class Program
    {
        /// <span class="code-SummaryComment"><summary></span>
        /// Encrypt a string.
        /// <span class="code-SummaryComment"></summary></span>
        /// <span class="code-SummaryComment"><param name="originalString">The original string.</param></span>
        /// <span class="code-SummaryComment"><returns>The encrypted string.</returns></span>
        /// <span class="code-SummaryComment"><exception cref="ArgumentNullException">This exception will be </span>
        /// thrown when the original string is null or empty.<span class="code-SummaryComment"></exception></span>
        public static string EncryptDES(string inName, string outName, string originalString, byte[]  key)
        {
            FileStream fin = new FileStream(inName, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);
            //Create variables to help with read and write.
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
            long rdlen = 0;              //This is the total number of bytes written.
            long totlen = fin.Length;    //This is the total length of the input file.
            int len;                     //This is the number of bytes to be written at a time.
           
            if (String.IsNullOrEmpty(originalString))
            {
            }
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
            cryptoProvider.CreateEncryptor(key, key), CryptoStreamMode.Write);
            StreamWriter writer = new StreamWriter(cryptoStream);
            writer.Write(originalString);
            writer.Flush();
            cryptoStream.FlushFinalBlock();
            writer.Flush();
            return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
        }
        /// <span class="code-SummaryComment"><summary></span>
        /// Decrypt a crypted string.
        /// <span class="code-SummaryComment"></summary></span>
        /// <span class="code-SummaryComment"><param name="cryptedString">The crypted string.</param></span>
        /// <span class="code-SummaryComment"><returns>The decrypted string.</returns></span>
        /// <span class="code-SummaryComment"><exception cref="ArgumentNullException">This exception will be thrown </span>
        /// when the crypted string is null or empty.<span class="code-SummaryComment"></exception></span>
        public static string DecryptDES(string inName, string outName, string cryptedString,byte[] key)
        {
            FileStream fin = new FileStream(inName, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);
            //Create variables to help with read and write.
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
            long rdlen = 0;              //This is the total number of bytes written.
            long totlen = fin.Length;    //This is the total length of the input file.
            int len;                     //This is the number of bytes to be written at a time.
          
            if (String.IsNullOrEmpty(cryptedString))
            {
            }
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream
                    (Convert.FromBase64String("cryptedString"));
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
                cryptoProvider.CreateDecryptor(key, key), CryptoStreamMode.Read);
            StreamReader reader = new StreamReader(cryptoStream);
            return reader.ReadToEnd();
        }
        private static void EncryptDataAES(string inName, string outName, byte[] aesKey, byte[] aesIV)
        {
            //Create the file streams to handle the input and output files.
            FileStream fin = new FileStream(inName, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);

            //Create variables to help with read and write.
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
            long rdlen = 0;              //This is the total number of bytes written.
            long totlen = fin.Length;    //This is the total length of the input file.
            int len;                     //This is the number of bytes to be written at a time.

            Aes aes = Aes.Create();
            CryptoStream encStream = new CryptoStream(fout, aes.CreateEncryptor(aesKey, aesIV), CryptoStreamMode.Write);

            Console.WriteLine("Encrypting...");

            //Read from the input file, then encrypt and write to the output file.
            while (rdlen < totlen)
            {
                len = fin.Read(bin, 0, 100);
                encStream.Write(bin, 0, len);
                rdlen = rdlen + len;
                Console.WriteLine("{0} bytes processed", rdlen);
            }

            encStream.Close();
            fout.Close();
            fin.Close();
        }
        public static void EncryptTextToFileDES(string text, string path, byte[] key, byte[] iv)
        {
            try
            {
                // Create or open the specified file.
                using (FileStream fStream = File.Open(path, FileMode.Create))
                // Create a new DES object.
                using (DES des = DES.Create())
                // Create a DES encryptor from the key and IV
                using (ICryptoTransform encryptor = des.CreateEncryptor(key, iv))
                // Create a CryptoStream using the FileStream and encryptor
                using (var cStream = new CryptoStream(fStream, encryptor, CryptoStreamMode.Write))
                {
                    // Convert the provided string to a byte array.
                    byte[] toEncrypt = Encoding.UTF8.GetBytes(text);

                    // Write the byte array to the crypto stream.
                    cStream.Write(toEncrypt, 0, toEncrypt.Length);
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                throw;
            }
        }

        public static string DecryptTextFromFileDES(string path, byte[] key, byte[] iv)
        {
            try
            {
                // Open the specified file
                using (FileStream fStream = File.OpenRead(path))
                // Create a new DES object.
                using (DES des = DES.Create())
                // Create a DES decryptor from the key and IV
                using (ICryptoTransform decryptor = des.CreateDecryptor(key, iv))
                // Create a CryptoStream using the FileStream and decryptor
                using (var cStream = new CryptoStream(fStream, decryptor, CryptoStreamMode.Read))
                // Create a StreamReader to turn the bytes back into text
                using (StreamReader reader = new StreamReader(cStream, Encoding.UTF8))
                {
                    // Read back all of the text from the StreamReader, which receives
                    // the decrypted bytes from the CryptoStream, which receives the
                    // encrypted bytes from the FileStream.
                    return reader.ReadToEnd();
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                throw;
            }
        }
        static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var enc1251 = Encoding.GetEncoding(1251);

            System.Console.OutputEncoding = System.Text.Encoding.UTF8;
            System.Console.InputEncoding = enc1251;

            var vaiant = 9;
            Console.WriteLine("1.	Для выполнения работы сгенерировать ключ шифрования заданной длинны "+
                "в соответствии с вариантом (см. таблицу) Для генерации использовать генератор случайны  х" +
                " чисел. Записать ключ в файл. ");
            Console.WriteLine("Вариант:= " + vaiant);
            var P = Math.Pow(10, -4);
            var V = 3*60*24*7; //  3 password per min - pawword per week
            var T = 20/7;// 20 дней - 20/7 недель . 
            var S = V * T / P;
            Console.WriteLine("P:= " + vaiant);
            Console.WriteLine("V:= " + vaiant);
            Console.WriteLine("T:= " + vaiant);
            Console.WriteLine("*S:= "+S);
            var A = 66; // руссский прописные + русские строчные буквы. 
            var i = 0;
            while (S > Math.Pow(A, i))
            {
                Console.WriteLine("A:= "+A+" , L:= "+i+" , S:="+Math.Pow(A, i));
                i++;
            }
            i++;
            Console.WriteLine("A:= "+ A);
            Console.WriteLine("L:= "+i);
            Console.WriteLine("S:= " + Math.Pow(A, i));
            //--//
            Console.WriteLine("2.	Написать приложение, шифрующие текст по алгоритму DES. "+
                 "  Ключ шифрования и шифруемый текст считать из файла. Написать приложение, дешифрующие текст по алгоритму DES." +
                "   Ключ шифрования и криптограмму считать из файла. ");
            dynamic codec = new DESCryptoServiceProvider();
            
        string pathMessage = "C:\\Users\\admin\\source\\repos\\ZI_Laba3\\ZI_Laba3\\stateIn.txt";
        string pathKey = "C:\\Users\\admin\\source\\repos\\ZI_Laba3\\ZI_Laba3\\key.txt";
            byte[] bytes;
            dynamic key;
            dynamic iv;
            using (DES des = DES.Create())
            {
                key = des.Key;
                iv = des.IV;
            }
            using (StreamWriter writer = new StreamWriter(pathKey, false))
            {
                 writer.WriteLine(key);
            }
            /* using (StreamReader reader = new StreamReader(pathkey))
             {
                 //key =  reader.ReadToEnd();
                  bytes = ASCIIEncoding.ASCII.GetBytes(key);
                 codec.Key = bytes;

                 //txtEncryptedData.Text = encryptedData;
                 Console.WriteLine(key);
             }*/

            // Создаем экземпляр нашего класса
            // и передаем ему выбранный шифровальшик
            ExecuteCryptography executeCryptography =
                new ExecuteCryptography(codec);
         
            // асинхронное чтение
            dynamic sourceData; dynamic encryptedData;
            using (StreamReader reader = new StreamReader(pathMessage))
            {
                 sourceData = reader.ReadToEnd();
                 encryptedData = executeCryptography.Encrypt(sourceData);
                //txtEncryptedData.Text = encryptedData;
            }
            // Шифруем текст
            encryptedData = executeCryptography.Encrypt(sourceData);
            Console.WriteLine("encryptedData DES:= "+encryptedData);
            //EncryptTextToFileDES(sourceData, pathMessage, key, iv);
            // Расшифровываем текст
            string decryptedData = executeCryptography.Decrypt(encryptedData);
            Console.WriteLine("decryptedData DES:= "+decryptedData);
            Console.WriteLine("3.	Написать приложение, шифрующие текст по алгоритму TripleDES." +
                " Ключ шифрования и шифруемый текст считать из файла. Написать приложение, дешифрующие текст по алгоритму TripleDES. " +
                "  Ключ шифрования и криптограмму считать из файла. ");
            codec = new TripleDESCryptoServiceProvider();
             executeCryptography =
             new ExecuteCryptography(codec);
            using (StreamReader reader = new StreamReader(pathMessage))
            {
                sourceData = reader.ReadToEnd();
                encryptedData = executeCryptography.Encrypt(sourceData);
                //txtEncryptedData.Text = encryptedData;
            }
            // Шифруем текст
            encryptedData = executeCryptography.Encrypt(sourceData);
            Console.WriteLine("encryptedData  TripleDES:= " + encryptedData);
            //EncryptTextToFileDES(sourceData, pathMessage, key, iv);
            // Расшифровываем текст
             decryptedData = executeCryptography.Decrypt(encryptedData);
            Console.WriteLine("decryptedData  TripleDES:= " + decryptedData);
            // Decrypt the file back to a string.
            // string decrypted = DecryptTextFromFileDES(pathMessage, key, iv);

            // Display the decrypted string to the console.
            //Console.WriteLine(decrypted);
            Console.WriteLine("4.	Написать приложение, шифрующие текст по алгоритму AES. " +
                "  Ключ шифрования и шифруемый текст считать из файла. Написать приложение," +
                " дешифрующие текст по алгоритму AES.   Ключ шифрования и криптограмму считать из файла. ");
            codec = SymmetricAlgorithm.Create();
            executeCryptography =
            new ExecuteCryptography(codec);
            using (StreamReader reader = new StreamReader(pathMessage))
            {
                sourceData = reader.ReadToEnd();
                encryptedData = executeCryptography.Encrypt(sourceData);
                //txtEncryptedData.Text = encryptedData;
            }
            // Шифруем текст
            encryptedData = executeCryptography.Encrypt(sourceData);
            Console.WriteLine("encryptedData  SymmetricAlgorithm:= " + encryptedData);
            //EncryptTextToFileDES(sourceData, pathMessage, key, iv);
            // Расшифровываем текст
            decryptedData = executeCryptography.Decrypt(encryptedData);
            Console.WriteLine("decryptedData  SymmetricAlgorithm:= " + decryptedData);
            Console.WriteLine("5.	Написать приложение, шифрующие текст по алгоритму Rijndael. " +
                "  Ключ шифрования и шифруемый текст считать из файла. Написать приложение, " +
                "дешифрующие текст по алгоритму Rijndael.   " +
                "Ключ шифрования и криптограмму считать из файла. ");

            codec = new RijndaelManaged();
            executeCryptography =
          new ExecuteCryptography(codec);
            using (StreamReader reader = new StreamReader(pathMessage))
            {
                sourceData = reader.ReadToEnd();
                encryptedData = executeCryptography.Encrypt(sourceData);
                //txtEncryptedData.Text = encryptedData;
            }
            // Шифруем текст
            encryptedData = executeCryptography.Encrypt(sourceData);
            Console.WriteLine("encryptedData  Rijndael:= " + encryptedData);
            //EncryptTextToFileDES(sourceData, pathMessage, key, iv);
            // Расшифровываем текст
            decryptedData = executeCryptography.Decrypt(encryptedData);
            Console.WriteLine("decryptedData  Rijndael:= " + decryptedData);
            //--//
            Console.ReadLine();
        }
    }
}
