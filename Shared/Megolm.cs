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
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoChat.Shared {

    // TODO: Maybe convert to C# API

    public class MegolmSession {
        public const int RatchetSize = 128;
        public Ed25519 Key { get; set; }
        public const byte Version = 0x03;
        public uint I { get; set; }
        public byte[] Ratchet { get; set; }

        // TODO: Separate meta from Session
        public string Name { get; set; }
        public X25519 Peer { get; set; }

        /// <summary>Link related sessions</summary>
        public MegolmSession Next { get; set; }
        public DateTime LastActive { get; set; }

        public MegolmSession() {
            Key = new Ed25519();
            Ratchet = new byte[RatchetSize];
            I = 0;
            Name = "Alice"; // TODO: Random Name generators

            using (var rng = new RNGCryptoServiceProvider()) {
                rng.GetBytes(Ratchet);
            }

            LastActive = DateTime.Now;
        }

        public MegolmSession(byte[] data) {
            Deserialize(data);
            LastActive = DateTime.Now;
        }

        public static MegolmSession Create(byte[] data) {
            return new MegolmSession(data);
        }

        public void Deserialize(byte[] data) {
            using (var stream = new MemoryStream(data))
            using (var br = new BinaryReader(stream)) {
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
                LastActive = DateTime.Now;
            }
        }

        public byte[] Serialize() {
            using (var stream = new MemoryStream()) {
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

        public static readonly byte[][] MegaOlmSeeds = new byte[][] {
            new byte[] {0x00},
            new byte[] {0x01},
            new byte[] {0x02},
            new byte[] {0x03}
        };

        private void Rehash(int from, int to) {
            const int PartLength = RatchetSize / 4;

            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(Ratchet, PartLength * from, PartLength));
            hmac.BlockUpdate(MegaOlmSeeds[to], 0, 1);
            hmac.DoFinal(Ratchet, PartLength * to);
        }

        public void Advance() {
            LastActive = DateTime.Now;
            Console.WriteLine($"Advance: {I} -> {I + 1} {LastActive}");
            ++I;

            if (I % 0xFFFFFF == 0) {
                Rehash(0, 3);
                Rehash(0, 2);
                Rehash(0, 1);
                Rehash(0, 0);
            }
            else if (I % 0xFFFF == 0) {
                Rehash(1, 3);
                Rehash(1, 2);
                Rehash(1, 1);
            }
            else if (I % 0xFF == 0) {
                Rehash(2, 3);
                Rehash(2, 2);
            }
            else {
                Rehash(3, 3);
            }
        }
    }



    sealed public class MegolmGroup {
        public MegolmSession Session { get; set; }
        Dictionary<string, MegolmSession> Peers { get; set; }
        public List<MegolmSession> PeerList => Peers.Values.ToList();

        public readonly byte[] Info = System.Text.Encoding.UTF8.GetBytes("MEGOLM_KEYS");

        public MegolmGroup() {
            Peers = new Dictionary<string, MegolmSession>();
            Session = new MegolmSession();

            Peers.Add(Session.Key.PublicKeyBase64, Session);
        }

        public static byte[] GetRandomBytes(int length) {
            SecureRandom prng = new SecureRandom();

            return SecureRandom.GetNextBytes(prng, length);
        }

        public string GetPeerName(byte[] k) {
            return Peers[Convert.ToBase64String(k)].Name;
        }

        public IEnumerable<MegolmSession> CurrentPeers => PeerList.Where(p => p.Next == null);

        public IEnumerable<MegolmSession> ActivePeers =>
            CurrentPeers.Where(p => (DateTime.Now - p.LastActive).TotalSeconds <= 90);
        public IEnumerable<MegolmSession> InactivePeers =>
            CurrentPeers.Where(p => (DateTime.Now - p.LastActive).TotalSeconds > 90);

        /// Return True if new Peer
        public bool AddPeer(MegolmSession session) {
            Console.WriteLine("Add Peer");

            // Error, or at least warn
            if (Peers.ContainsKey(session.Key.PublicKeyBase64))
                return false;

            Console.WriteLine($"pc: {Peers.Count}");

            // Track equal X25519 keys for eventual cleanup
            foreach (var peer in Peers.Values) {
                var p1 = BitConverter.ToString(peer.Peer.PublicKey);
                var p2 = BitConverter.ToString(session.Peer.PublicKey);
                Console.WriteLine($"pn: {peer.Next}\n  -{p1}\n  +{p2}");
                if (peer.Peer.Equals(session.Peer) && peer.Next == null) {
                    Console.WriteLine("next");
                    peer.Next = session;
                }
            }

            Peers.Add(session.Key.PublicKeyBase64, session);
            Console.WriteLine($"Peer: {session.Key.PublicKeyBase64} {session.Peer == null}");

            return true;
        }

        public bool AddPeer(byte[] data) {
            var session = MegolmSession.Create(data);
            return AddPeer(session);
        }


        static public byte[] HKDF(byte[] ikm, int length, byte[] salt, byte[] info) {
            IDigest hash = new Sha256Digest();

            var p = new HkdfParameters(ikm, salt, info);
            var okm = new byte[length];

            var hkdf = new HkdfBytesGenerator(hash);
            hkdf.Init(p);
            hkdf.GenerateBytes(okm, 0, length);

            return okm;
        }

        public byte[] Encrypt(Message msg) {
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
            // TODO: reconcile this, we don't advance because we expect to 
            // decrypt own messages.
            // Session.Advance();

            msg.MessageIndex = (int)Session.I;
            msg.CipherIV = aesIV;
            msg.Encrypt(aesKey);

            return msg.Compute(hmacKey, Session.Key);
        }

        /*
        public byte[] Encrypt(byte[] payload) {
            var msg = new Message();
            return Encrypt(msg);
        }
        */

        public MegolmSession Decrypt(Message msg) {
            // TODO: Prettify, bug or security if this fails.
            var peer = Peers[msg.Sender.PublicKeyBase64];

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

            msg.Decrypt(aesKey);

            return peer;
        }
    }
}