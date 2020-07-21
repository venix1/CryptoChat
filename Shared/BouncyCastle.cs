// Helpers for Bouncy Castle to abstract it's use.

using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Rfc7748 = Org.BouncyCastle.Math.EC.Rfc7748;
using Rfc8032 = Org.BouncyCastle.Math.EC.Rfc8032;

namespace CryptoChat.Shared
{

    public static class BouncyCastle
    {

        public static readonly SecureRandom SecureRandom;

        static BouncyCastle()
        {
            SecureRandom = new Org.BouncyCastle.Security.SecureRandom();
        }
        static public byte[] AesCrypt(bool encrypt, byte[] aesKey, byte[] aesIV, byte[] payload)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", aesKey);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7PADDING");
            cipher.Init(encrypt, new ParametersWithIV(key, aesIV));
            return cipher.DoFinal(payload);
        }

        static public byte[] HmacSha256(byte[] key, byte[] data)
        {
            IMac hmac = MacUtilities.GetMac("HMac-SHA256");
            hmac.Init(new KeyParameter(key));
            hmac.Reset();
            hmac.BlockUpdate(data, 0, data.Length);
            return MacUtilities.DoFinal(hmac);
        }

        static public byte[] Sha256Sum(byte[] data)
        {
            IDigest hash = new Sha256Digest();
            hash.BlockUpdate(data, 0, data.Length);

            byte[] output = new byte[hash.GetByteLength()];
            hash.DoFinal(output, 0);
            return output;
        }
    }

    public class X25519
    {
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }

        public X25519()
        {
            PrivateKey = new byte[32];
            PublicKey = new byte[32];

            Rfc7748.X25519.ScalarMultBase(PrivateKey, 0, PublicKey, 0);
        }

        public X25519(byte[] privateKey, byte[] publicKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
        }

        public (byte[], byte[]) ComputeSharedSecret(X25519 publicKey) {
            return ComputeSharedSecret(publicKey.PublicKey);
        }
        
        public (byte[], byte[]) ComputeSharedSecret(byte[] publicKey)
        {
            byte[] secret = new byte[64]; // aes + hmac
            byte[] aesKey = new byte[32];
            byte[] hmacKey = new byte[32];
            Rfc7748.X25519.ScalarMult(PrivateKey, 0, publicKey, 0, secret, 0);
            Array.Copy(secret, 0, aesKey, 0, aesKey.Length);
            Array.Copy(secret, aesKey.Length, hmacKey, 0, hmacKey.Length);
            return (aesKey, hmacKey);
        }
    }

    public class Ed25519
    {
        public static readonly int PrivateKeySize = Rfc8032.Ed25519.SecretKeySize;
        public static readonly int PublicKeySize = Rfc8032.Ed25519.PublicKeySize;

        public byte[] PublicKey { get; set; }
        public string PublicKeyBase64 => Convert.ToBase64String(PublicKey);
        public byte[] PrivateKey { get; set; }

        static Ed25519()
        {
            Rfc8032.Ed25519.Precompute();
        }


        private void Initialize()
        {
            PrivateKey = new byte[Rfc8032.Ed25519.SecretKeySize];
            PublicKey = new byte[Rfc8032.Ed25519.PublicKeySize];
        }

        public Ed25519()
        {
            Initialize();

            BouncyCastle.SecureRandom.NextBytes(PrivateKey);

            Rfc8032.Ed25519.GeneratePublicKey(PrivateKey, 0, PublicKey, 0);
        }

        public Ed25519(byte[] privateKey)
        {
            Initialize();

            Array.Copy(privateKey, PrivateKey, privateKey.Length);

            Rfc8032.Ed25519.GeneratePublicKey(PrivateKey, 0, PublicKey, 0);
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
                PrivateKey = null;
            }
            else
            {
                privateKey.CopyTo(PrivateKey, 0);
            }

            if (publicKey == null)
            {
                Rfc8032.Ed25519.GeneratePublicKey(PrivateKey, 0, PublicKey, 0);
            }
            else
            {
                Console.WriteLine($"{publicKey.Length} {PublicKey.Length}");
                publicKey.CopyTo(PublicKey, 0);
            }
        }

        public byte[] Sign(byte[] data, int offset, int length)
        {
            // Console.WriteLine($"Ed25519.Sign: {offset}, {length}");
            var signature = new byte[Rfc8032.Ed25519.SignatureSize];

            Rfc8032.Ed25519.Sign(PrivateKey, 0, data, offset, length, signature, 0);

            return signature;
        }

        public bool Verify(byte[] sig, byte[] data)
        {
            return Verify(sig, 0, data, 0, data.Length);
        }

        public bool Verify(byte[] sig, int sigOffset, byte[] data, int dataOffset, int dataLength)
        {
            return Rfc8032.Ed25519.Verify(sig, sigOffset, PublicKey, 0, data, dataOffset, dataLength);
        }

        public byte[] Export()
        {
            var copy = new byte[PublicKey.Length];
            PublicKey.CopyTo(copy, 0);
            return copy;
        }
    }
}