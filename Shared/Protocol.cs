using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace CryptoChat.Shared
{
    // TODO: Revamp Message layout. Code has 3 values, Group, Session, Peer
    // Group, Session, Peer can further subclass after decryption.
    public abstract class Message
    {
        public abstract byte Code { get; }
        public static Dictionary<byte, Type> Children { get; set; }
        public long MessageIndex { get; set; }
        /// <summary>Unencrypted data, typically a public key</summary>
        public byte[] PlainText { get; set; }
        public byte[] CipherIV { get; set; }
        public byte[] CipherText { get; set; }


        public bool Verified { get; set; }
        public byte[] Bytes { get; set; }
        public byte[] MAC { get; set; }
        public byte[] Signature { get; set; }
        public Ed25519 Sender { get; set; }

        static Message()
        {
            Children = new Dictionary<byte, Type>();

            var messageInfo = typeof(Message).GetTypeInfo();
            foreach (var child in messageInfo.Assembly.GetTypes())
            {

                if (child.IsSubclassOf(messageInfo))
                {
                    Children[(byte)child.GetField("ProtocolCode").GetValue(null)] = child;
                }
            }
        }

        public Message()
        {
            MAC = new byte[8];
            Signature = new byte[64];
            CipherIV = new byte[16];
            PlainText = new byte[0];
            CipherText = new byte[0];
        }

        public static Message Parse(byte[] data)
        {
            byte version = data[0];

            Type messageType;
            if (!Children.TryGetValue(version, out messageType))
            {
                // TODO: Make warning
                throw new Exception($"Debug, missing message {version}");
            }

            using (var stream = new MemoryStream(data))
            {
                var msg = (Message)System.Activator.CreateInstance(messageType);
                msg.Parse(stream);
                msg.Bytes = data;
                return msg;
            }
        }

        public void Encrypt(byte[] key)
        {
            PreEncrypt();
            if (CipherIV == null)
                BouncyCastle.SecureRandom.NextBytes(CipherIV);
            CipherText = BouncyCastle.AesCrypt(true, key, CipherIV, CipherText);
        }
        public void Decrypt(byte[] key)
        {
            CipherText = BouncyCastle.AesCrypt(false, key, CipherIV, CipherText);
            PostDecrypt();
        }

        /// Hooks so messages can prepare CipherText
        abstract protected void PreEncrypt();
        abstract protected void PostDecrypt();

        public bool Verify(byte[] hmacKey, Ed25519 key)
        {
            // This should not fail.
            if (Sender.PublicKey != key.PublicKey)
                throw new Exception("Sender doesn't match");
            if (!key.Verify(Signature, new ReadOnlySpan<byte>(Bytes, 0, Bytes.Length - Signature.Length).ToArray()))
                throw new Exception("Sender verification failed");

            // Check authenticity, All recipients receive same messages
            // Failure is expected.
            var offset = Signature.Length + 32 + MAC.Length;
            var message = new ReadOnlySpan<byte>(Bytes, 0, Bytes.Length - offset);
            var result = BouncyCastle.HmacSha256(hmacKey, message.ToArray());
            if (!result.Take(8).SequenceEqual(MAC)) {
                Console.WriteLine("INFO: Message HMAC failure");
                Console.WriteLine(BitConverter.ToString(result.Take(8).ToArray()));
                Console.WriteLine(BitConverter.ToString(MAC));
                return false;
            }

            return true;
        }

        public byte[] Compute(byte[] hmacKey, Ed25519 key)
        {
            var stream = new MemoryStream();
            stream.WriteByte(Code);
            WriteMessageIndex(stream);
            WritePlainText(stream);
            WriteCipherIV(stream);
            WriteCipherText(stream);

            var hmac = stream.Position;
            Console.WriteLine($"HMAC: {stream.Position}");
            var result = BouncyCastle.HmacSha256(hmacKey, stream.ToArray());
            stream.Write(result, 0, 8);

            stream.Write(key.PublicKey); // Sender identification
            result = key.Sign(stream.GetBuffer(), 0, (int)stream.Position);
            stream.Write(result, 0, result.Length);

            return stream.ToArray();
        }

        private void WriteMessageIndex(Stream stream)
        {
            WriteInteger(stream, 0x08);  // Message-Index
            WriteInteger(stream, MessageIndex);
        }

        private void WriteCipherIV(Stream stream)
        {
            WriteInteger(stream, 0x0A);  // Cipher-IV
            WriteString(stream, CipherIV);
        }

        private void WritePlainText(Stream stream)
        {
            WriteInteger(stream, 0x04); // Cipher-Text
            WriteString(stream, PlainText);
        }
        private void WriteCipherText(Stream stream)
        {
            WriteInteger(stream, 0x12); // Cipher-Text
            WriteString(stream, CipherText);
        }

        protected void WriteInteger(Stream stream, long integer)
        {
            ulong value = (ulong)integer;
            byte b = 0;

            int start = (int)stream.Position;

            do
            {
                b = (byte)(value & 0b0111_1111);
                value >>= 7;

                if (value != 0)
                    b |= 0b1000_0000;

                stream.WriteByte(b);
            } while (value != 0);
            int end = (int)stream.Position;
            Console.WriteLine(BitConverter.ToString(new ReadOnlySpan<byte>(((MemoryStream)stream).GetBuffer(), start, end - start).ToArray()));
        }

        protected void WriteString(Stream stream, byte[] value)
        {
            if (value == null)
                value = new byte[0];

            WriteInteger(stream, value.Length);
            stream.Write(value, 0, value.Length);
        }

        public void Parse(Stream stream)
        {
            if (Code != stream.ReadByte())
            {
                throw new Exception("Protocol mismatch");
            }

            // Read Message-Index & Cipher-Text
            // TODO: Some form of error checking
            ReadTag(stream); // Message-Index
            ReadTag(stream); // PlainText
            ReadTag(stream); // Cipher-IV
            ReadTag(stream); // Cipher-Text

            var hmac = stream.Position;

            stream.Read(MAC); // Not Known

            var sender = new byte[32];
            stream.Read(sender);
            Sender = new Ed25519(null, sender);
            stream.Read(Signature);

            Console.WriteLine($"Lengths: {hmac} {stream.Position} {stream.Position - hmac}");
            Console.WriteLine($"{stream.Length} {stream.Position}");
            if (stream.Length != stream.Position)
                throw new Exception("Excess data in message");
        }

        protected void ReadTag(Stream stream)
        {
            var tag = ReadInteger(stream);
            switch (tag)
            {
                case 0x08: // Message-Index
                    MessageIndex = ReadInteger(stream);
                    break;
                case 0x12: // Cipher-Text
                    CipherText = ReadString(stream);
                    break;
                case 0x04: // Plain-Text
                    PlainText = ReadString(stream);
                    break;
                case 0x0A: // Cipher-IV
                    CipherIV = ReadString(stream);
                    break;
                case 0x0C: // Cipher-IV
                    // CipherSalt = ReadString(stream);
                    break;
                default:
                    throw new Exception($"Unknown Tag: {tag:X}");

            }
        }

        protected int ReadInteger(Stream stream)
        {
            int value = 0;
            byte b = 0;
            int shifts = 0;

            do
            {
                b = (byte)stream.ReadByte();
                Console.WriteLine($"{b:X}");
                value |= (b & 0b0111_1111) << shifts;
                shifts += 7;
            }
            while ((b & 0b1000_0000) > 0);

            return value;
        }

        protected byte[] ReadString(Stream stream)
        {
            var length = ReadInteger(stream);

            byte[] buffer = new byte[length];
            stream.Read(buffer);

            return buffer;
        }
    }

    public class MetaMessage : Message
    {
        public static byte ProtocolCode = 0x03;
        override public byte Code => MetaMessage.ProtocolCode;

        public string Key { get; set; }
        public string Value { get; set; }

        public MetaMessage() : base() { }
        public MetaMessage(string key, string value) : this()
        {
            Console.WriteLine($"MetaMessage: {key} {value}");
            Key = key;
            Value = value;
        }

        override protected void PreEncrypt()
        {
            using (var stream = new MemoryStream())
            {
                WriteString(stream, System.Text.Encoding.UTF8.GetBytes(Key));
                WriteString(stream, System.Text.Encoding.UTF8.GetBytes(Value));
                CipherText = stream.ToArray();
            }
        }
        override protected void PostDecrypt()
        {
            using (var stream = new MemoryStream(CipherText))
            {
                Key = System.Text.Encoding.UTF8.GetString(ReadString(stream));
                Value = System.Text.Encoding.UTF8.GetString(ReadString(stream));
            }
        }
    }

    /// Accept request to join conversation
    public class PeerHandshake : Message
    {
        public static byte ProtocolCode = 0x02;
        override public byte Code => PeerHandshake.ProtocolCode;

        public MegolmSession Session { get; set; }

        public PeerHandshake() : base() { }

        public PeerHandshake(MegolmSession session) : this()
        {
            Session = session;
        }

        override protected void PreEncrypt()
        {
            CipherText = Session.Serialize();
        }
        override protected void PostDecrypt()
        {
            Session = MegolmSession.Create(CipherText);
        }
    }

    /// <summary>
    /// Indicate desire to join converstation 
    /// </summary>
    public class JoinMessage : Message
    {

        public static byte ProtocolCode = 0x01;
        override public byte Code => JoinMessage.ProtocolCode;

        public X25519 EncryptKey { get; set; }
        public Ed25519 SignKey { get; set; }

        public JoinMessage() : base() { }

        public JoinMessage(Ed25519 signKey, X25519 encryptKey) : this()
        {
            // TODO: use Ed25519 for both
            EncryptKey = encryptKey;
            SignKey = signKey;
        }

        override protected void PreEncrypt()
        {
            using (var stream = new MemoryStream())
            {
                WriteString(stream, EncryptKey.PublicKey);
                WriteString(stream, SignKey.PublicKey);
                CipherText = stream.ToArray();
                Console.WriteLine($"PreJoin: {CipherText.Length} {EncryptKey.PublicKey.Length} {SignKey.PublicKey.Length}");
            }
        }
        override protected void PostDecrypt()
        {
            using (var stream = new MemoryStream(CipherText))
            {
                var encryptKey = ReadString(stream);
                var signKey = ReadString(stream);
                Console.WriteLine($"PostJoin: {CipherText.Length} {encryptKey.Length} {signKey.Length}");
                EncryptKey = new X25519(null, encryptKey);
                SignKey = new Ed25519(null, signKey);
            }
        }
    }
}