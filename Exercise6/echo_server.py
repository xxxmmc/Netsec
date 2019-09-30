import asyncio
import escape_room_006
import time
import playground
import gamePackage
from playground.network.packet import PacketType
import autograder_ex6_packets
from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
class EchoServer(asyncio.Protocol):
        def __init__(self):
            pass 
        def connection_made(self, transport):
            print("connection made")
            self.transport = transport
            self.game = escape_room_006.EscapeRoomGame(output = self.send)
            self.game.create_game()
            self.game.start()
            self.loop = asyncio.get_event_loop()
            self.loop.create_task(self.flyingkey_event())
        def data_received(self, data):
            d = PacketType.Deserializer()
            d.update(data)
            for gamePacket in d.nextPackets():
                print(gamePacket.comd)
                command = gamePacket.comd;
                self.game.command(command)
           # data_send = self.game.command(command[0])
        def send(self, data):
            gameBackPacket = gamePackage.GameResponsePacket.create_game_response_packet(data,self.game.status)
            print(gameBackPacket.reps)
            self.transport.write(gameBackPacket.__serialize__())
            time.sleep(0.25)
        async def flyingkey_event(self):
            await asyncio.wait([asyncio.ensure_future(a) for a in self.game.agents]) 
if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        #EnablePresetLogging(PRESET_DEBUG)
        coro = playground.create_server(EchoServer,'localhost',31000)
        server = loop.run_until_complete(coro)
         
        try:
	        loop.run_forever()
        except KeyboardInterrupt:
                pass
        server.close()
        loop.run_until_complete(server.wait_close())
        loop.close()


