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
        packet = autograder_ex6_packets.AutogradeStartTest(name="Yu MAO", email="ymao@jhu.edu", team=5, port=31000)
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
                if isinstance(gamePacket,autograder_ex6_packets.AutogradeTestStatus):
                    print("Got {} from server.".format(gamePacket.test_id))
                    print(gamePacket.submit_status)
                    print(gamePacket.client_status)
                    print(gamePacket.server_status)
                    print(gamePacket.error) 
                
                    gameInitPacket = gamePackage.GameInitPacket.create_game_init_packet("test")
                    self.transport.write(gameInitPacket.__serialize__())
                    print("good")
                elif isinstance(gamepacket,gamePackage.GameRequirePayPacket):
                    print(ok)
                    print(gamePacket.process_game_require_pay_packet())
                    if (gamePacket.check_check_game_require_pay_packet):
                        gameResponsePacket = gamePackage.GameResponsePacket.create_game_response_packet("","dead")
                    else:
                        gamePayPacket = gamePackage.GamePayPacket.create_game_pay_packet("your receipt","team5")
                        self.transport.write(gamePayPacket.__serialize__())
                elif isinstance(gamePacket,gamePackage.GameResponsePacket):                
                    print(gamePacket.response())
                    if self.count < 5:
                        print("first")
                        gameCommandPacket = gamePackage.GameCommandPacket.create_game_command_packet(self.good_list[self.count])
                        print(gameCommandPacket.command())
                        self.transport.write(gameCommandPacket.__serialize__())
                        self.count += 1
                        print(self.count)
                        time.sleep(0.25)
                    elif self.count == 5 and gamePacket.response().split()[-1] == 'wall':
                        gameCommandPacket = gamePackage.GameCommandPacket.create_game_command_packet("hit flyingkey with hammer")
                        self.transport.write(gameCommandPacket.__serialize__())
                        self.count += 1;
                        time.sleep(0.25)
                    elif self.count > 5:
                        if self.count2 < 4:
                            gameCommandPacket = gamePackage.GameCommandPacket.create_game_command_packet(self.good_list2[self.count2])
                            self.transport.write(gameCommandPacket.__serialize__())
                            self.count2 += 1
                     
    def sendAutogradedata(self):
            #self.Autogradedata = autograder_exi6_packets.AutogradeStartTest(name = None,team = None,email = None,port = None,packet_file = b"")
            #print("qwe")
            packet = AutogradeStartTest(name="Yu Mao", email="ymao@jhu.edu", team=5, port=22000)
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
        #EnablePresetLogging(PRESET_DEBUG)
        coro = playground.create_connection(EchoClient,'20194.0.0.19000',19007)
        client = loop.run_until_complete(coro)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        client.close()
        loop.run_until_complete(client.close())
        loop.close()



