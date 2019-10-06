import asyncio
import time
import playground
#import gamePackage
from playground.network.packet import PacketType
import autograder_ex6_packets
#from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
from bankPackage import *
#from gamePackage import *
import mypacket
from mypacket import *
class EchoClient(asyncio.Protocol):
    def __init__(self):
            #self.deserializer = EchoPacket.Deserializer()
            self.good_list = ["look mirror","get hairpin","unlock chest with hairpin","open chest","get hammer in chest"]
            self.good_list2 = [" ","get key","unlock door with key","open door"]
            self.count = 0;
            self.flag = 0;
            self.hitflag = 0;
            self.count2 = 0;
            self.loop = asyncio.get_event_loop()
           # EnablePresetLogging(PRESET_DEBUG)
    def connection_made(self, transport):
        self.transport = transport;
        packet = autograder_ex6_packets.AutogradeStartTest(name="Yuchen Yang", email="yc.yang@jhu.edu", team=5, port=8988)
        self.transport.write(packet.__serialize__())
        self.command_packet = create_game_init_packet("Yuchen Yang")
        self.transport.write(self.command_packet.__serialize__())
    def data_received(self, data):
            d = PacketType.Deserializer()
            d.update(data)
            print("received")
            for gamePacket in d.nextPackets():
                if isinstance(gamePacket,autograder_ex6_packets.AutogradeTestStatus):
                    print("Got {} from server.".format(gamePacket.test_id))
                    print(gamePacket.submit_status)
                    print(gamePacket.client_status)
                    print(gamePacket.server_status)
                    print(gamePacket.error)  
                elif isinstance(gamePacket,mypacket.GameRequirePayPacket):
                    print(gamePacket.amount)
                    unique_id, account, amount = process_game_require_pay_packet(gamePacket)
                    print(unique_id)
                    print(account)
                    print(amount)
                    self.loop.create_task(self.Create_Payment(account, amount, unique_id))
                elif isinstance(gamePacket, mypacket.GameResponsePacket):
                    print(gamePacket.response)
                    if self.count < 5:
                        gameCommandPacket = create_game_command(self.good_list[self.count])
                        print(gameCommandPacket.command)
                        self.transport.write(gameCommandPacket.__serialize__())
                        self.count += 1
                        print(self.count)
                        time.sleep(0.25)
                    elif self.count == 5 and gamePacket.response.split()[-1] == 'wall':
                        gameCommandPacket = create_game_command("hit flyingkey with hammer")
                        self.transport.write(gameCommandPacket.__serialize__())
                        self.count += 1;
                        time.sleep(0.25)
                    elif self.count > 5:
                        if self.count2 < 4:
                            gameCommandPacket = create_game_command(self.good_list2[self.count2])
                            self.transport.write(gameCommandPacket.__serialize__())
                            self.count2 += 1
    async def Create_Payment(self, account, amount, unique_id):
        result = await Payment_Init("yyang179_account", account, amount, unique_id)
        print(result)
    
        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        self.transport.write(game_packet.__serialize__())
if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        #EnablePresetLogging(PRESET_DEBUG)
        coro = playground.create_connection(EchoClient,'20194.0.0.19000',19008)
        client = loop.run_until_complete(coro)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        client.close()
        loop.run_until_complete(client.close())
        loop.close()

