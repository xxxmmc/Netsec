import asyncio, time, sys, os, logging
import playground
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG, PRESET_VERBOSE
from autograder_ex6_packets import *
import my_packet_file
from my_packet_file import *
from ConductPay import *

message = ["look", "look mirror", "get hairpin", "look chest", "unlock chest with hairpin",
           "open chest", "look in chest", "get hammer from chest", "hit flyingkey with hammer",
           "get key", "unlock door with key", "open door"]

async def myconductpay(account,amount,unique_id,transport):
    result = await makepay("wbai3", account, amount, unique_id)
    print(res)
    ok, receipt, receiptSignature = result
    print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",receipt,receiptSignature)
    packet = create_game_pay_packet(receipt, receiptSignature)
    transport.write(packet.__serialize__())



class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.transport = transport
        packet = AutogradeStartTest(name="Haoran Xu", email="xuhaoran0805@outlook.com", team=5, port=8855)
        print("connection_made")
        with open("my_packet_file.py", "rb") as f:
            print(1111111111)
            packet.packet_file = f.read()
        self.transport.write(packet.__serialize__())
        self.command_packet = my_packet_file.GameCommandPacket.create_game_command_packet("Submit")
        self.transport.write(self.command_packet.__serialize__())
        self.i = 0

    def data_received(self, data_bytes):
        print("!!!!!")
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
                packet = create_game_init_packet("Haoran Xu")
                self.transport.write(packet.__serialize__())
            if isinstance(packet, GameResponsePacket):
                response, status = process_game_response(packet)
                print("GameResponse:",response, status)

                if self.i < 8:
                    print(packet.response())
                    print(message[self.i])
                    self.command_packet = my_packet_file.GameCommandPacket.create_game_command_packet(message[self.i])
                    self.transport.write(self.command_packet.__serialize__())
                    self.i = self.i+1
                    time.sleep(1)
                elif data[0].response().split()[-1]=="wall":
                    print(data[0].response())
                    print(message[self.i])
                    self.command_packet = my_packet_file.GameCommandPacket.create_game_command_packet(message[8])
                    self.transport.write(self.command_packet.__serialize__())
                    time.sleep(1)
                    self.i = self.i + 1
                elif self.i >8 and self.i < len(message):
                    print(data[0].response())
                    print(message[self.i])
                    self.command_packet = my_packet_file.GameCommandPacket.create_game_command_packet(message[self.i])
                    self.transport.write(self.command_packet.__serialize__())
                    self.i = self.i + 1
                    time.sleep(0.5)
            if isinstance(packet,GamePaymentRequestPacket):
                unique_id, account, amount = process_game_require_pay_packer(packet)
                print("GameRequirePayPacket:",unique_id, account, amount)
                asyncio.ensure_future(myconductpay(account,amount,unique_id,transport))

if __name__=="__main__":
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    EnablePresetLogging(PRESET_DEBUG)
    coro = playground.create_connection(EchoClient, '20194.0.0.19000', 19007)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


