import asyncio
import time
import playground
#import gamePackage
from playground.network.packet import PacketType
import autograder_ex6_packets
from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
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

        self.command_packet = create_game_init_packet("YU Mao")
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

    async def Create_Payment(self, account, amount, unique_id):
        result = await Payment_Init("ymao22", account, amount, unique_id)
        print(result)

        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        print(game_packet)
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
    #team2
    destnationaddress = '20194.2.57.98'      
    destinationport = '2222' 
    #team3
    #destinationaddress = '20194.3.6.9'      
    #destinationport = '333' 
    #team4
    #destinationaddress = '20194.4.4.4'      
    #destinationport = '8666' 
    #team6
    #destinationaddress = '20194.6.20.30'
    #destinationport = '16666'
    #team9
    #destinationaddress = '20194.9.1.1'
    #destinationport = '7826'
    coro = playground.create_connection(EchoClient, 'crap://20194.4.4.4', 8666)
    loop.set_debug(enabled=True)
    from playground.common.logging import EnablePresetLogging, PRESET_DEBUG 
    EnablePresetLogging(PRESET_DEBUG)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
