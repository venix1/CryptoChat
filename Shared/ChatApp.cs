using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoChat.Shared {
    public class ChatEntry {
        public DateTime Timestamp { get; set; }
        public Peer Peer { get; set; }
        public Message Message { get; set; }
    }

    public class Peer {
        public int Index { get; set; }
        public X25519 Key { get; set; }
        public List<MegolmSession> Sessions { get; set; }
        public MegolmSession CurrentSession => Sessions.First();

        public Peer(X25519 publicKey) {
            Sessions = new List<MegolmSession>();
        }

        void ReplaceSession(MegolmSession session) {
            Sessions.Prepend(session);
        }
    }

    public class CryptoChat {
        private int NextPeer = 0;
        public Ed25519 ClientKey { get; set; }
        public X25519 PeerKey { get; set; }
        public Dictionary<string, Peer> Peers { get; set; }
        public IEnumerable<Peer> ActivePeers => Peers.Values.Where(p => (DateTime.Now - p.CurrentSession.LastActive).TotalSeconds <= 90);
        public IEnumerable<Peer> InactivePeers => Peers.Values.Where(p => DateTime.Now.Subtract(p.CurrentSession.LastActive).TotalSeconds > 90);

        public byte[] GroupSalt { get; set; }
        public byte[] GroupKey { get; set; }
        public byte[] GroupHmac { get; set; }


        public MegolmGroup Group { get; set; }
        public Guid Channel { get; set; }

        public const int CostFactor = 256; // 2^14;
        public const int BlockSize = 8;
        // public const int Parallelization = 1;

        Func<byte[], Task> Send { get; set; }

        public List<string> History = new List<string>();

        // Peers
        // Group
        // Session
        private CryptoChat() {
            GroupKey = new byte[32];
            GroupSalt = new byte[32];
            GroupHmac = new byte[32];

            PeerKey = new X25519();
            ClientKey = new Ed25519();
            Peers = new Dictionary<string, Peer>();

            Group = new MegolmGroup();
            Group.Session.Peer = PeerKey;
            Console.WriteLine("Client Peer: {0}", BitConverter.ToString(PeerKey.PublicKey));
        }

        public CryptoChat(Func<byte[], Task> fn, byte[] group, byte[] passwd) : this() {
            byte[] result = SCrypt.Generate(passwd, group, CostFactor, BlockSize, 1, 112);
            Array.Copy(result, 0, GroupKey, 0, 32);
            Array.Copy(result, 32, GroupSalt, 0, 32);
            Array.Copy(result, 64, GroupHmac, 0, 32);
            Send = fn;
            Channel = new Guid(new ReadOnlySpan<byte>(result, 96, 16));

            /*
            Console.WriteLine("Room: {0}\n  AesKey: {1}\n  Salt: {2}\n  Hmac: {3}",
                Channel.ToString(),
                BitConverter.ToString(GroupKey),
                BitConverter.ToString(GroupSalt),
                BitConverter.ToString(GroupHmac));
            */
        }

        public async Task Join() {
            var msg = new JoinMessage(ClientKey, PeerKey);
            await SendGroup(msg);
        }

        public async Task SetNick(string name) {
            Group.Session.Name = name;
            if (Group.PeerList.Count <= 1) // Ignore self
                return;

            var msg = new MetaMessage("SetNick", name);
            await SendSession(msg);
        }

        public async Task Ping() {
            var msg = new MetaMessage("ping", "pong");
            await SendSession(msg);

            // Check for inactive players, force key rotation.
            await Rekey();
            // Purge sessions older than 15 minutes
        }

        public async Task TextMessage(string text) {
            var msg = new MetaMessage("text", text);
            await SendSession(msg);
        }

        private async Task SendSession(Message msg) {
            var payload = SessionEncrypt(msg);
            await Send(payload);
        }

        private async Task Rekey() {
            Console.WriteLine("Rekey");
            // Duplicate Session
            // Group.Session = MegolmSession.Create(Group.Session.Serialize());
            var session = new MegolmSession();
            session.I = Group.Session.I;
            session.LastActive = Group.Session.LastActive;
            session.Name = Group.Session.Name;
            session.Peer = Group.Session.Peer;
            session.Ratchet = Group.Session.Ratchet;
            session.Key = new Ed25519();
            Group.Session = session;
            Group.AddPeer(Group.Session);

            foreach (var peer in Group.CurrentPeers) {
                if (PeerKey.Equals(peer.Peer))
                    continue;
                Console.WriteLine($"Rekey: {peer.Peer}:");
                await SendMegolmSession(peer.Peer);
            }
        }

        private async Task SendGroup(Message msg) {
            // Encrypts with Group key
            // Macs with group key
            // Signs with Client key
            msg.Encrypt(GroupKey);
            await Send(msg.Compute(GroupHmac, ClientKey));
        }

        /// <summary> Encrypt peer, HMAC peer, Sign client</summary>
        private async Task SendPeer(X25519 peer, Message msg) {
            (var aesKey, var hmacKey) = PeerKey.ComputeSharedSecret(peer.PublicKey);
            msg.PlainText = PeerKey.PublicKey;
            msg.Encrypt(aesKey);
            await Send(msg.Compute(hmacKey, ClientKey));
        }

        public async Task OnMessage(byte[] message) {
            var msg = Message.Parse(message);

            var jmpTable = new Dictionary<byte, Func<Message, Task>>() {
                {JoinMessage.ProtocolCode, OnJoinMessage},
                {PeerHandshake.ProtocolCode, OnPeerHandshake},
                {MetaMessage.ProtocolCode, OnMetaMessage},
            };

            try {
                Console.WriteLine($"Received: {msg.GetType()}");
                var fn = jmpTable[msg.Code];
                await fn(msg);
            }
            catch (KeyNotFoundException ex) {
                throw ex;
            }
        }

        public async Task OnJoinMessage(Message m) {
            var msg = (JoinMessage)m;
            GroupDecrypt(msg);

            // Ignore own join message
            if (msg.SignKey.Equals(ClientKey))
                return;

            // Create new Peer
            var peer = new Peer(msg.EncryptKey);
            peer.Index = NextPeer++;
            Peers.Add(peer.Key.PublicKeyBase64, peer);

            await SendMegolmSession(peer);
        }

        public async Task SendMegolmSession(Peer peer) {
            await SendMegolmSession(peer.Key);
        }

        public async Task SendMegolmSession(X25519 peer) {
            var reply = new PeerHandshake(Group.Session);

            await SendPeer(peer, reply);
        }

        public Task OnMetaMessage(Message m) {
            var msg = (MetaMessage)m;

            var session = SessionDecrypt(msg);

            switch (msg.Key) {
                case "text":
                    History.Add($"{session.Name}: {msg.Value}");
                    break;
                case "ping":
                    session.LastActive = DateTime.Now;
                    Console.WriteLine("pong: {0}", session.LastActive);
                    break;
                default:
                    break;
            }

            return Task.FromResult(true);
        }

        private async Task OnPeerHandshake(Message m) {
            var msg = (PeerHandshake)m;

            var peer = new X25519(null, msg.PlainText);

            (var aesKey, var hmac) = PeerKey.ComputeSharedSecret(peer);

            // Failure is expected. 
            // All handshakes trigger this, but only known peers will validate.
            if (!msg.Verify(hmac, msg.Sender))
                return;

            if (PeerKey.Equals(peer))
                return;

            msg.Decrypt(aesKey);
            msg.Session.Peer = peer;

            // New Peer needs session info
            if (Group.AddPeer(msg.Session)) {
                await SendMegolmSession(new X25519(null, msg.PlainText));
            }
            else {
                Console.WriteLine("Duplicate Peer: {0}\n  {1}", msg.Session.Key.PublicKeyBase64, Group.Session.Key.PublicKeyBase64);
            }
        }

        private void OnPeerSession(Stream stream) {

        }

        public byte[] GroupEncrypt(Message msg) {
            BouncyCastle.SecureRandom.NextBytes(msg.CipherIV);
            msg.MessageIndex = 0;
            msg.Encrypt(GroupKey);

            return msg.Compute(GroupHmac, ClientKey);
        }

        public void GroupDecrypt(Message msg) {
            if (!msg.Verify(GroupHmac, msg.Sender))
                throw new Exception("Unable to validate Group message");

            msg.Decrypt(GroupKey);
        }

        public byte[] SessionEncrypt(Message msg) {
            return Group.Encrypt(msg);
        }

        public MegolmSession SessionDecrypt(Message msg) {
            return Group.Decrypt(msg);
        }

        public byte[] PeerEncrypt(X25519 peer, Message msg) {
            (var aesKey, var hmacKey) = PeerKey.ComputeSharedSecret(peer.PublicKey);
            BouncyCastle.SecureRandom.NextBytes(msg.CipherIV);
            msg.MessageIndex = 0;
            msg.Encrypt(aesKey);

            return msg.Compute(hmacKey, ClientKey);
        }

        public Message PeerDecrypt(X25519 peer, Message msg) {
            (var aesKey, var hmacKey) = PeerKey.ComputeSharedSecret(peer.PublicKey);
            // msg.Verify(hmacKey);
            // V | payload | mac | signature(peer)
            msg.Decrypt(aesKey);
            return msg;
        }
    }
}