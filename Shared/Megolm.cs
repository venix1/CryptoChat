// https://gitlab.matrix.org/matrix-org/olm/blob/master/docs/megolm.md

// Session
// a 32 bit counter, i = 0
// an Ed25519 keypair, K
// byte[4] R = 4 bytes of True Random
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Rfc8032 = Org.BouncyCastle.Math.EC.Rfc8032;

namespace CryptoChat.Shared
{

    // TODO: Maybe convert to C# API
    public class Ed25519
    {
        public static readonly int PrivateKeySize = Rfc8032.Ed25519.SecretKeySize;
        public static readonly int PublicKeySize = Rfc8032.Ed25519.PublicKeySize;

        public byte[] PublicKeyRaw { get; set; }
        public string PublicKeyBase64 => Convert.ToBase64String(PublicKeyRaw);
        public byte[] PrivateKeyRaw { get; set; }

        static Ed25519()
        {
            Rfc8032.Ed25519.Precompute();
        }


        private void Initialize()
        {
            PrivateKeyRaw = new byte[Rfc8032.Ed25519.SecretKeySize];
            PublicKeyRaw = new byte[Rfc8032.Ed25519.PublicKeySize];
        }

        public Ed25519()
        {
            Initialize();

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(PrivateKeyRaw);
            }

            Rfc8032.Ed25519.GeneratePublicKey(PrivateKeyRaw, 0, PublicKeyRaw, 0);
        }

        public Ed25519(byte[] privateKey)
        {
            Initialize();

            Array.Copy(privateKey, PrivateKeyRaw, privateKey.Length);

            Rfc8032.Ed25519.GeneratePublicKey(PrivateKeyRaw, 0, PublicKeyRaw, 0);
        }

        public Ed25519(byte[] privateKey, byte[] publicKey)
        {
            Initialize();

            if (privateKey == null && publicKey == null)
            {
                throw new Exception("Must have key data");
            }

            if (privateKey == null)
            {
                PrivateKeyRaw = null;
            }
            else
            {
                privateKey.CopyTo(PrivateKeyRaw, 0);
            }

            if (publicKey == null)
            {
                Rfc8032.Ed25519.GeneratePublicKey(PrivateKeyRaw, 0, PublicKeyRaw, 0);
            }
            else
            {
                // Console.WriteLine($"{publicKey.Length} {PublicKeyRaw.Length}");
                publicKey.CopyTo(PublicKeyRaw, 0);
            }
        }

        public byte[] Sign(byte[] data, int offset, int length)
        {
            // Console.WriteLine($"Ed25519.Sign: {offset}, {length}");
            var signature = new byte[Rfc8032.Ed25519.SignatureSize];

            Rfc8032.Ed25519.Sign(PrivateKeyRaw, 0, data, offset, length, signature, 0);

            var dHash = BitConverter.ToString(SHA256.Create().ComputeHash(data, offset, length));
            var sHash = BitConverter.ToString(SHA256.Create().ComputeHash(signature));
            var kHash = BitConverter.ToString(SHA256.Create().ComputeHash(PublicKeyRaw, 0, PublicKeyRaw.Length));
            // Console.WriteLine($"{sHash} - {dHash} - {kHash}");
            // Console.WriteLine(BitConverter.ToString(PublicKeyRaw));

            return signature;
        }

        public bool Verify(byte[] sig, byte[] data)
        {
            return Verify(sig, 0, data, 0, data.Length);
        }

        public bool Verify(byte[] sig, int sigOffset, byte[] data, int dataOffset, int dataLength)
        {
            // Ed25519  .Sign(sk, 0, m, 0, mLen, sig1, 0);
            // Ed25519.Verify(sig1, 0, pk, 0, m, 0, mLen);
            // Console.WriteLine($"Ed25519.Verify: {sigOffset}, {dataOffset}, {dataLength}");
            var dHash = BitConverter.ToString(SHA256.Create().ComputeHash(data, dataOffset, dataLength));
            var sHash = BitConverter.ToString(SHA256.Create().ComputeHash(sig, sigOffset, sig.Length - sigOffset));
            var kHash = BitConverter.ToString(SHA256.Create().ComputeHash(PublicKeyRaw, 0, PublicKeyRaw.Length));
            // Console.WriteLine($"{sHash} - {dHash} - {kHash}");
            // Console.WriteLine(BitConverter.ToString(PublicKeyRaw));

            return Rfc8032.Ed25519.Verify(sig, sigOffset, PublicKeyRaw, 0, data, dataOffset, dataLength);
        }

        public byte[] Export()
        {
            var copy = new byte[PublicKeyRaw.Length];
            PublicKeyRaw.CopyTo(copy, 0);
            return copy;
        }
    }

    public class MegolmSession
    {
        public const int RatchetSize = 128;
        public Ed25519 Key { get; set; }
        public const byte Version = 0x03;
        public uint I { get; set; }
        public byte[] Ratchet { get; set; }
        public string Name { get; set; }

        public MegolmSession()
        {
            Key = new Ed25519();
            Ratchet = new byte[RatchetSize];
            I = 0;
            Name = "Alice"; // TODO: Random Name generators

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(Ratchet);
            }

            // Random.NextBytes(PrivateKey);
        }

        public MegolmSession(byte[] data)
        {
            Deserialize(data);
        }

        public static MegolmSession Create(byte[] data)
        {
            return new MegolmSession(data);
        }

        public void Deserialize(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            using (var br = new BinaryReader(stream))
            {
                /*
                 +---+----+--------+--------+--------+--------+------+-----------+
                | V | i  | R(i,0) | R(i,1) | R(i,2) | R(i,3) | Kpub | Signature |
                +---+----+--------+--------+--------+--------+------+-----------+
                0   1    5        37       69      101      133    165         229   bytes
                */

                if (br.ReadByte() != Version)
                    throw new Exception("Invalid Session");

                I = br.ReadUInt32();
                Ratchet = br.ReadBytes(RatchetSize);
                Key = new Ed25519(null, br.ReadBytes(Ed25519.PublicKeySize));
                var length = br.ReadByte();
                Name = Encoding.UTF8.GetString(br.ReadBytes(length));

                if (!Key.Verify(data, (int)stream.Position, data, 0, (int)stream.Position))
                    throw new Exception("Failed to verify Session");
            }
        }

        public byte[] Serialize()
        {
            using (var stream = new MemoryStream())
            {
                stream.WriteByte(Version);
                stream.Write(BitConverter.GetBytes(I));
                stream.Write(Ratchet);
                stream.Write(Key.Export());
                var bytes = Encoding.UTF8.GetBytes(Name);
                stream.WriteByte((byte)bytes.Length);
                stream.Write(bytes);

                // Console.WriteLine(BitConverter.ToString(SHA256.Create().ComputeHash(stream.GetBuffer(), 0, (int)stream.Position)));
                stream.Write(Key.Sign(stream.GetBuffer(), 0, (int)stream.Position));

                return stream.ToArray();
            }
        }

        public void Advance()
        {
            // TODO: Update Ratchet.
            ++I;
        }
    }

    public class Message
    {
        public const int Version = 0x03;
        public long MessageIndex { get; set; }
        public byte[] CipherText { get; set; }
        public byte[] MAC { get; set; }
        public byte[] Signature { get; set; }

        public Message()
        {
            MAC = new byte[8];
            Signature = new byte[64];
        }

        public static Message Parse(byte[] data)
        {
            var ms = new MemoryStream(data);
            if (ms.ReadByte() != Version)
                throw new Exception("Expected V2 message");

            var msg = new Message();
            msg.Parse(ms);
            return msg;
        }

        public byte[] Compute(byte[] hmacKey, Ed25519 key)
        {
            // HMAC-SHA-256
            var hmac = HMACSHA256.Create();
            hmac.Key = hmacKey;

            var stream = new MemoryStream();
            stream.WriteByte(Version);
            WriteMessageIndex(stream);
            WriteCipherText(stream);

            var result = hmac.ComputeHash(stream.ToArray());
            stream.Write(result, 0, 8);

            result = key.Sign(stream.GetBuffer(), 0, (int)stream.Position);
            stream.Write(result, 0, result.Length);

            return stream.ToArray();
        }

        private void WriteMessageIndex(Stream stream)
        {
            WriteInteger(stream, 0x08);  // Message-Index
            WriteInteger(stream, MessageIndex);
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
                throw new Exception("Handle null string");
            WriteInteger(stream, value.Length);
            stream.Write(value, 0, value.Length);
        }

        public void Parse(Stream stream)
        {
            // Read Message-Index & Cipher-Text
            ReadTag(stream);
            ReadTag(stream);

            stream.Read(MAC);
            stream.Read(Signature);

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

    sealed public class MegolmGroup
    {
        public MegolmSession Session { get; set; }
        Dictionary<string, MegolmSession> Peers { get; set; }
        public List<MegolmSession> PeerList => Peers.Values.ToList();

        public readonly byte[] Info = System.Text.Encoding.UTF8.GetBytes("MEGOLM_KEYS");

        public MegolmGroup()
        {
            Peers = new Dictionary<string, MegolmSession>();
            Session = new MegolmSession();

            Peers.Add(Session.Key.PublicKeyBase64, Session);
        }

        public static byte[] GetRandomBytes(int length)
        {
            SecureRandom prng = new SecureRandom();

            return SecureRandom.GetNextBytes(prng, length);
        }

        public string GetPeerName(byte[] k)
        {
            return Peers[Convert.ToBase64String(k)].Name;
        }

        /// Return True if new Peer
        public bool AddPeer(byte[] data)
        {
            var session = MegolmSession.Create(data);

            // Error, or at least warn
            if (Peers.ContainsKey(session.Key.PublicKeyBase64))
                return false;

            Peers.Add(session.Key.PublicKeyBase64, session);
            Console.WriteLine($"Peer: {session.Key.PublicKeyBase64}");

            return true;
        }


        static public byte[] HKDF(byte[] ikm, int length, byte[] salt, byte[] info)
        {
            IDigest hash = new Sha256Digest();

            var p = new HkdfParameters(ikm, salt, info);
            var okm = new byte[length];

            var hkdf = new HkdfBytesGenerator(hash);
            hkdf.Init(p);
            hkdf.GenerateBytes(okm, 0, length);

            return okm;
        }

        // Generic encrypt/decrypt with AES
        static public byte[] AesCrypt(bool encrypt, byte[] aesKey, byte[] hmacKey, byte[] aesIV, byte[] payload)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", aesKey);
            IBufferedCipher inCipher = CipherUtilities.GetCipher("AES/CBC/PKCS7PADDING");
            inCipher.Init(encrypt, new ParametersWithIV(key, aesIV));
            return inCipher.DoFinal(payload);
        }

        // Performs HKDF, then encrypt/decrypt with AES-CBC
        static public byte[] AesCrypt(byte[] ikm, byte[] salt, byte[] info, bool encrypt, byte[] data)
        {
            var okm = MegolmGroup.HKDF(ikm, 80, salt, info);

            byte[] aesKey = new byte[32];
            byte[] hmacKey = new byte[32];
            byte[] aesIV = new byte[16];
            salt = MegolmGroup.GetRandomBytes(32);

            Array.Copy(okm, 0, aesKey, 0, aesKey.Length);
            Array.Copy(okm, aesKey.Length, hmacKey, 0, hmacKey.Length);
            Array.Copy(okm, aesKey.Length + hmacKey.Length, aesIV, 0, aesIV.Length);

            return AesCrypt(encrypt, aesKey, hmacKey, aesIV, data);
        }

        public byte[] Encrypt(byte[] payload)
        {
            // Console.WriteLine($"Encrypt: {payload}");
            // AES_KEYi | HMAC_KEYi​ | AES_IVi​ ​ = HKDF(0,Ri​,"MEGOLM_KEYS",80)​
            // HKDF = HKDF-SHA_256 (salt, ikm, info, Length)
            // TODO: DRY - Share between Encrypt/Decrypt
            byte[] aesKey = new byte[32];
            byte[] hmacKey = new byte[32];
            byte[] aesIV = new byte[16];
            var okm = HKDF(Session.Ratchet, 80, null, Info);
            Array.Copy(okm, 0, aesKey, 0, aesKey.Length);
            Array.Copy(okm, aesKey.Length, hmacKey, 0, hmacKey.Length);
            Array.Copy(okm, aesKey.Length + hmacKey.Length, aesIV, 0, aesIV.Length);
            Session.Advance();

            var msg = new Message();
            msg.MessageIndex = (int)Session.I++;
            msg.CipherText = AesCrypt(true, aesKey, hmacKey, aesIV, payload);

            var oHash = BitConverter.ToString(SHA256.Create().ComputeHash(okm));
            var cHash = BitConverter.ToString(SHA256.Create().ComputeHash(msg.CipherText));
            Console.WriteLine($"Encrypt: {oHash} {cHash}");

            // Console.WriteLine("Done Encrypt");

            return msg.Compute(hmacKey, Session.Key);
        }



        public byte[] Decrypt(byte[] id, byte[] data)
        {
            // TODO: This is an error, make it pretty. Should Abort chat(channel secrecy is compromised)
            var peer = Peers[Convert.ToBase64String(id)];
            var msg = Message.Parse(data);

            // TODO: DRY - HKDF
            byte[] aesKey = new byte[32];
            byte[] hmacKey = new byte[32];
            byte[] aesIV = new byte[16];
            var okm = HKDF(peer.Ratchet, 80, null, Info);
            Array.Copy(okm, 0, aesKey, 0, aesKey.Length);
            Array.Copy(okm, aesKey.Length, hmacKey, 0, hmacKey.Length);
            Array.Copy(okm, aesKey.Length + hmacKey.Length, aesIV, 0, aesIV.Length);

            // msg.Verify(hmacKey, peer.Key);
            // TODO: Compare Session.I & msg.MessageIndex
            peer.Advance();

            var oHash = BitConverter.ToString(SHA256.Create().ComputeHash(okm));
            var cHash = BitConverter.ToString(SHA256.Create().ComputeHash(msg.CipherText));
            Console.WriteLine($"Decrypt: {oHash} {cHash}");

            return AesCrypt(false, aesKey, hmacKey, aesIV, msg.CipherText);
        }
    }
}