import asyncio
import time
import playground
import gamePackage
from playground.network.packet import PacketType
import autograder_ex6_packets
from playground.common.logging import EnablePresetLogging,PRESET_DEBUG

class EchoClient(asyncio.Protocol):
    def __init__(self):
            #self.deserializer = EchoPacket.Deserializer()
            self.good_list = ["look mirror","get hairpin","unlock chest with hairpin","open chest","get hammer in chest"]
            self.good_list2 = [" ","get key","unlock door with key","open door"]
            self.count = 0;
            self.flag = 0;
            self.hitflag = 0;
            self.count2 = 0;
           # EnablePresetLogging(PRESET_DEBUG)
    def connection_made(self, transport):
            #self.deserializer = AutogradeTestStatus.Deserializer()
        #print("m")
        self.transport = transport;
        packet = autograder_ex6_packets.AutogradeStartTest(name="Yu MAO", email="ymao@jhu.edu", team=5, port=19005)
        with open("gamePackage.py", "rb") as f:
            packet.packet_file = f.read()
        self.transport.write(packet.__serialize__())
        #print("good")
        
    def data_received(self, data):
            #print("mmy")
            #print("mmy")
            d = PacketType.Deserializer()
            d.update(data)
            for gamePacket in d.nextPackets():
                print("Got {} from server.".format(gamePacket.test_id))
                print(gamePacket.submit_status)
                print(gamePacket.client_status)
                print(gamePacket.server_status)
                print(gamePacket.error)
                print(gamePacket.commend)             
            if self.count < 5:
                #print("first")
                GameCommandPacket = gamePackage.GameCommandPacket.create_game_command_packet(self.good_list[self.count])
                self.transport.write(GameCommandPacket.__serialize__())
                #print(GameCommandPacket)
                #print("second")
                time.sleep(0.25)
                self.count += 1
            elif self.count == 5 and data.decode().split()[-1] == 'wall<EOL>':
                send("hit flyingkey with hammer")
                self.count += 1;
                #print("good")
                time.sleep(0.25)
            elif self.count > 5:
                if self.count2 < 4:
                    send(self.good_list2[self.count2])
                    self.count2 += 1
    def sendAutogradedata(self):
            #self.Autogradedata = autograder_exi6_packets.AutogradeStartTest(name = None,team = None,email = None,port = None,packet_file = b"")
            #print("qwe")
            packet = AutogradeStartTest(name="Yu Mao", email="ymao@jhu.edu", team=5, port=19005)
            with open("my_packet_file.py", "rb") as f:
                packet.packet_file = f.read()
            self.transport.write(packet.__serialize__())
    def send(self, data):
            GameCommandPacket = gamePackage.GameCommandPacket.create_game_command_packet(data)
            #print(GameCommandPacket)
            self.transport.write(GameCommandPacket.__serialize__())
            
if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        EnablePresetLogging(PRESET_DEBUG)
        coro = playground.create_connection(EchoClient,'20194.0.0.19000',19006)
        client = loop.run_until_complete(coro)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        client.close()
        loop.run_until_complete(client.close())
        loop.close()

