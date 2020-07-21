using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;

namespace CryptoChat.Server.Hubs {
    public class ChatHub : Hub {


        public async Task JoinGroup(Guid group) {
            Console.WriteLine($"JoinGroup: {group.ToString()}");
            await Groups.AddToGroupAsync(Context.ConnectionId, group.ToString());
        }

        public async Task SendMessage(Guid group, byte[] message) {
            Console.WriteLine($"Message -> {group.ToString()}");
            await Clients.Group(group.ToString()).SendAsync("ReceiveMessage", message);
        }
    }
}