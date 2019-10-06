import asyncio, time, sys, os, logging
import playground
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG, PRESET_VERBOSE
from autograder_ex6_packets import *
import my_packet_file
from my_packet_file import *
from bankPackage import *

message = ["look", "look mirror", "get hairpin", "look chest", "unlock chest with hairpin",
           "open chest", "look in chest", "get hammer from chest", "hit flyingkey with hammer",
           "get key", "unlock door with key", "open door"]

async def myconductpay(account,amount,unique_id,transport):
    result = await makepay("wbai3_account", account, amount, unique_id)
    print(result)
    ok, receipt, receiptSignature = result
    print("receive receipt")
    packet = create_game_pay_packet(receipt, receiptSignature)
    transport.write(packet.__serialize__())



class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.transport = transport
        packet = AutogradeStartTest(name="Haoran Xu", email="xuhaoran0805@outlook.com", team=5, port=8855)
        self.transport.write(packet.__serialize__())
        self.init_packet = create_game_init_packet("Xuhr")
        self.transport.write(self.init_packet.__serialize__())
        self.i = 0

    def data_received(self, data_bytes):
        print("....")
        self.deserializer = PacketType.Deserializer()
        self.deserializer.update(data_bytes)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, AutogradeTestStatus):
                print("client_status:")
                print(packet.client_status)
                print("server_status:")
                print(packet.server_status)
                print("error:")
                print(packet.error)
                #packet = create_game_init_packet("Haoran Xu")
                #self.transport.write(packet.__serialize__())
            if isinstance(packet, GameResponsePacket):
                response, status = process_game_response(packet)
                print("GameResponse:",response)
                if self.i < 8:
                    print(message[self.i])
                    self.command_packet = create_game_command(message[self.i])
                    self.transport.write(self.command_packet.__serialize__())
                    self.i = self.i+1
                    time.sleep(1)
                elif response.split()[-1]=="wall":
                    print(message[self.i])
                    self.command_packet = create_game_command(message[8])
                    self.transport.write(self.command_packet.__serialize__())
                    time.sleep(1)
                    self.i = self.i + 1
                elif self.i >8 and self.i < len(message):
                    print(message[self.i])
                    self.command_packet = create_game_command(message[self.i])
                    self.transport.write(self.command_packet.__serialize__())
                    self.i = self.i + 1
                    time.sleep(1)
            if isinstance(packet,GameRequirePayPacket):
                unique_id, account, amount = process_game_require_pay_packet(packet)
                print("*****************GameRequirePayPacket:*****************",unique_id, account, amount)
                asyncio.ensure_future(myconductpay(account,amount,unique_id,self.transport))
                time.sleep(0.5)

if __name__=="__main__":
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    #EnablePresetLogging(PRESET_DEBUG)
    coro = playground.create_connection(EchoClient, '20194.0.0.19000', 19008)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


