import asyncio
import time
import playground
from playground.network.packet import PacketType
from autograder_ex6_packets import *
from bankPackage import *
import sys
import mypacket
from mypacket import *

message = ["look", "look mirror", "get hairpin", "look chest", "unlock chest with hairpin",
           "open chest", "look in chest", "get hammer from chest", "hit flyingkey with hammer",
           "get key", "unlock door with key", "open door"]



class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.loop = asyncio.get_event_loop()
        self.loop.add_reader(sys.stdin, self.game_next_input)
        self.i = 0
        self.transport = transport

        self.command_packet = create_game_init_packet("Bo")
        self.transport.write(self.command_packet.__serialize__())

    def data_received(self, data):
        d = PacketType.Deserializer()
        d.update(data)

        for gamePacket in d.nextPackets():
            print(gamePacket)
            if isinsitance(gamePacket, GameRequirePayPacket):
                print("_____")
                print(gamePacket.amount)
                unique_id, account, amount = process_game_require_pay_packet(gamePacket)
                print(unique_id)
                print(account)
                print(amount)
                self.loop.create_task(self.Create_Payment(account, amount, unique_id))
            elif isinstance(gamePacket, mypacket.GameResponsePacket):
                print(gamePacket.response)
                self.flush_output(gamePacket.response())
                if self.i == 0:
                    self.flush_output(">>", end=' ')
                    self.i +=1
            else:
                print("sadasd")

    async def Create_Payment(self, account, amount, unique_id):
        result = await Payment_Init("yyang179_account", account, amount, unique_id)
        print(result)

        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        self.transport.write(game_packet.__serialize__())

    def flush_output(self, *args, **kargs):
        print(*args, **kargs)
        sys.stdout.flush()

    def game_next_input(self):
        input = sys.stdin.readline().strip()
        self.command_packet = create_game_command(input)
        self.transport.write(self.command_packet.__serialize__())


if __name__ == "__main__":
    loop = asyncio.get_event_loop()

    coro = playground.create_connection(EchoClient, '20194.0.1.1', 16665)

    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

