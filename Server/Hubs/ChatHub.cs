using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;

namespace CryptoChat.Server.Hubs
{
    public class ChatHub : Hub
    {


        public async Task JoinGroup(Guid group, byte[] salt, byte[] session) {
            Console.WriteLine($"JoinGroup: {group.ToString()}");
            await Groups.AddToGroupAsync(Context.ConnectionId, group.ToString());
            
            // TODO: This shouldn't be done
            await Clients.OthersInGroup(group.ToString()).SendAsync("ReceiveSession", salt, session);
        }

        public async Task SendSession(Guid group, byte[] salt, byte[] session) {
            Console.WriteLine($"SendSession: {group.ToString()}");
            await Clients.OthersInGroup(group.ToString()).SendAsync("ReceiveSession", salt, session);
        }

        public async Task SendMessage(Guid group, byte[] k, byte[] message)
        {
            Console.WriteLine($"Message -> {group.ToString()}");
            await Clients.Group(group.ToString()).SendAsync("ReceiveMessage", k, message);
        }
    }
}