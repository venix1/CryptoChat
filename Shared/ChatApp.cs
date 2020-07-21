using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoChat.Shared
{

    public class Peer
    {
        byte[] PublicKey { get; set; }
        Peer(byte[] publicKey)
        {

        }
    }
    public class CryptoChat
    {
        public Ed25519 ClientKey { get; set; }
        public byte[] GroupSalt { get; set; }
        public byte[] GroupKey { get; set; }
        public byte[] GroupHmac { get; set; }
        public X25519 PeerKey { get; set; }
        public Dictionary<byte[], X25519> Peers { get; set; }

        public MegolmGroup Group { get; set; }
        public Guid Channel { get; set; }

        public const int CostFactor = 256; // 2^14;
        public const int BlockSize = 8;

        Func<byte[], Task> Send { get; set; }

        public List<string> History = new List<string>();

        // Peers
        // Group
        // Sessionublic const int Parallelization = 1;
        private CryptoChat()
        {
            GroupKey = new byte[32];
            GroupSalt = new byte[32];
            GroupHmac = new byte[32];

            PeerKey = new X25519();
            ClientKey = new Ed25519();

            Group = new MegolmGroup();
        }

        public CryptoChat(Func<byte[], Task> fn, byte[] group, byte[] passwd) : this()
        {
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

        public async Task Join()
        {
            var msg = new JoinMessage(ClientKey, PeerKey);
            await SendGroup(msg);
        }

        public async Task SetNick(string name)
        {
            Group.Session.Name = name;
            if (Group.PeerList.Count <= 1) // Ignore self
                return;

            var msg = new MetaMessage("SetNick", name);
            await SendSession(msg);
        }

        public async Task Ping()
        {
            var msg = new MetaMessage("ping", "pong");
            await SendSession(msg);
        }

        public async Task TextMessage(string text)
        {
            var msg = new MetaMessage("text", text);
            await SendSession(msg);
        }

        private async Task SendSession(Message msg)
        {
            var payload = SessionEncrypt(msg);
            await Send(payload);
        }

        private async Task SendGroup(Message msg)
        {
            // Encrypts with Group key
            // Macs with group key
            // Signs with Client key
            msg.Encrypt(GroupKey);
            await Send(msg.Compute(GroupHmac, ClientKey));
        }

        private async Task SendPeer(X25519 peer, Message msg)
        {
            // Encrypts with Peer key
            // Macs with Peer Key
            // Signs with Client key
            (var aesKey, var hmacKey) = PeerKey.ComputeSharedSecret(peer.PublicKey);
            msg.PlainText = peer.PublicKey;
            msg.Encrypt(aesKey);
            await Send(msg.Compute(hmacKey, ClientKey));
        }

        public async Task OnMessage(byte[] message)
        {
            var msg = Message.Parse(message);

            var jmpTable = new Dictionary<byte, Func<Message, Task>>() {
                {JoinMessage.ProtocolCode, OnJoinMessage},
                {PeerHandshake.ProtocolCode, OnPeerHandshake},
                {MetaMessage.ProtocolCode, OnMetaMessage},
            };

            try
            {
                Console.WriteLine($"Received: {msg.GetType()}");
                var fn = jmpTable[msg.Code];
                await fn(msg);
            }
            catch (KeyNotFoundException ex)
            {
                throw ex;
            }
        }

        public async Task OnJoinMessage(Message m)
        {
            var msg = (JoinMessage)m;
            GroupDecrypt(msg);

            if (msg.SignKey.PublicKey == ClientKey.PublicKey)
                return;

            await SendMegolmSession(msg.EncryptKey);
        }

        public async Task SendMegolmSession(X25519 peer)
        {
            var reply = new PeerHandshake(Group.Session);

            await SendPeer(peer, reply);
        }

        public Task OnMetaMessage(Message m)
        {
            var msg = (MetaMessage)m;

            var session = SessionDecrypt(msg);
            
            switch (msg.Key)
            {
                case "text":
                    History.Add($"{session.Name}: {msg.Value}");
                    break;
                case "ping":
                    Console.WriteLine("pong");
                    break;
                default:
                    break;
            }

            return Task.FromResult(true);
        }

        private async Task OnPeerHandshake(Message m)
        {
            var msg = (PeerHandshake)m;

            (var aesKey, var hmac) = PeerKey.ComputeSharedSecret(msg.PlainText);
            // Failure is expected. Any Handshake will trigger this.
            // Only expected peers validate.  
            if (!msg.Verify(hmac, msg.Sender))
            {
                return;
            }

            msg.Decrypt(aesKey);

            // New Peer needs session info
            if (Group.AddPeer(msg.Session))
            {
                await SendMegolmSession(new X25519(null, msg.PlainText));
            }
            else
            {
                Console.WriteLine("Duplicate Peer");
            }
        }

        private void OnPeerSession(Stream stream)
        {

        }

        public byte[] GroupEncrypt(Message msg)
        {
            BouncyCastle.SecureRandom.NextBytes(msg.CipherIV);
            msg.MessageIndex = 0;
            msg.Encrypt(GroupKey);

            return msg.Compute(GroupHmac, ClientKey);
        }

        public void GroupDecrypt(Message msg)
        {
            if (!msg.Verify(GroupHmac, msg.Sender))
                throw new Exception("Unable to validate Group message");

            msg.Decrypt(GroupKey);
        }

        public byte[] SessionEncrypt(Message msg)
        {
            return Group.Encrypt(msg);
        }

        public MegolmSession SessionDecrypt(Message msg)
        {
            return Group.Decrypt(msg);
        }

        public byte[] PeerEncrypt(X25519 peer, Message msg)
        {
            (var aesKey, var hmacKey) = PeerKey.ComputeSharedSecret(peer.PublicKey);
            BouncyCastle.SecureRandom.NextBytes(msg.CipherIV);
            msg.MessageIndex = 0;
            msg.Encrypt(aesKey);

            return msg.Compute(hmacKey, ClientKey);
        }

        public Message PeerDecrypt(X25519 peer, Message msg)
        {
            (var aesKey, var hmacKey) = PeerKey.ComputeSharedSecret(peer.PublicKey);
            // msg.Verify(hmacKey);
            // V | payload | mac | signature(peer)
            msg.Decrypt(aesKey);
            return msg;
        }
    }
}