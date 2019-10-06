import asyncio
import time
import playground
#import gamePackage
from playground.network.packet import PacketType
import autograder_ex6_packets
#from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
from bankPackage import *
import sys
#from gamePackage import *
import mypacket
from mypacket import *

class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.loop = asyncio.get_event_loop()
        self.loop.add_reader(sys.stdin, self.game_next_input)
        self.transport = transport

        self.command_packet = create_game_init_packet("Bo")
        self.transport.write(self.command_packet.__serialize__())

    def data_received(self, data):
        d = PacketType.Deserializer()
        d.update(data)
        for gamePacket in d.nextPackets():
            if isinstance(gamePacket, mypacket.GameRequirePayPacket):
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

    def game_next_input(self):
        input = sys.stdin.readline().strip()
        self.command_packet = create_game_command(input)
        self.transport.write(self.command_packet.__serialize__())


if __name__ == "__main__":
    loop = asyncio.get_event_loop()

    coro = playground.create_connection(EchoClient, 'localhost', 12414)

    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
