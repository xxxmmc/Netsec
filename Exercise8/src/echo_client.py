import asyncio
import time
import playground
import escape_room_packets
from playground.network.packet import PacketType
import autograder_ex6_packets
from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
from bankPackage import *
from escape_room_packets import *
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
            #self.deserializer = AutogradeTestStatus.Deserializer()
        #print("m")
        self.transport = transport;
        packet = autograder_ex6_packets.AutogradeStartTest(name="YU MAO", email="ymao@jhu.edu", team=5, port=21005)
        #with open("escape_room_packets.py", "rb") as f:
           # packet.packet_file = f.read()
        self.transport.write(packet.__serialize__())
        #print("good")
        self.gameinit_packet = create_game_init_packet("ymao22")
        self.transport.write(self.gameinit_packet.__serialize__())
    def data_received(self, data):
            #print("mmy")
            #print("mmy")
            d = PacketType.Deserializer()
            d.update(data)
            for gamePacket in d.nextPackets():
                if isinstance(gamePacket,autograder_ex6_packets.AutogradeTestStatus):
                    print("Got {} from server.".format(gamePacket.test_id))
                    print(gamePacket.submit_status)
                    print(gamePacket.client_status)
                    print(gamePacket.server_status)
                    print(gamePacket.error)  
                    print("good")
                elif isinstance(gamePacket,GameRequirePayPacket):
                    print(gamePacket.amount)
                    unique_id, account, amount = escape_room_packets.process_game_require_pay_packet(gamePacket)
                    print(unique_id)
                    print(account)
                    print(amount)
                    self.loop.create_task(self.Create_Payment(account, amount, unique_id))
                    print("endloop")
                elif isinstance(gamePacket,GameResponsePacket):
                    print(gamePacket.response)
                    print("this is a recep")
                    if self.count < 5:
                        print("first")
                        gameCommandPacket = create_game_command(self.good_list[self.count])
                        print(gameCommandPacket.command)
                        print("pass")
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
    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self.loop.stop()
    def sendAutogradedata(self):
            #self.Autogradedata = autograder_exi6_packets.AutogradeStartTest(name = None,team = None,email = None,port = None,packet_file = b"")
            #print("qwe")
            packet = AutogradeStartTest(name="Yu Mao", email="ymao@jhu.edu", team=5, port=21000)
            with open("my_packet_file.py", "rb") as f:
                packet.packet_file = f.read()
            self.transport.write(packet.__serialize__())
    def send(self, data):
            gameCommandPacket = create_game_command(data)
            #print(GameCommandPacket)
            self.transport.write(gameCommandPacket.__serialize__())
    async def Create_Payment(self, account, amount, unique_id):
        result = await Payment_Init("ymao22_account", account, amount, unique_id)
        print(result)
    
        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        self.transport.write(game_packet.__serialize__())
        print("newnewnew")
if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        EnablePresetLogging(PRESET_DEBUG)
        coro = playground.create_connection(EchoClient,'20194.0.0.19000',19008)
        client = loop.run_until_complete(coro)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        client.close()
        loop.run_until_complete(client.close())
        loop.close()





