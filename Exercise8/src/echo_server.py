import asyncio
import escape_room_006
import time
import playground
import escape_room_packets
from playground.network.packet import PacketType
import autograder_ex6_packets
from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
from escape_room_packets import *
class EchoServer(asyncio.Protocol):
        def __init__(self):
            pass 
        def connection_made(self, transport):
            print("connection made")
            self.transport = transport
        def data_received(self, data):
            d = PacketType.Deserializer()
            d.update(data)
            print("enter data_receive")
            for gamePacket in d.nextPackets():
                if isinstance(gamePacket,GameCommandPacket):
                    print(gamePacket.command)
                    command = gamePacket.command;
                    print("command")
                    self.game.command(command)
                elif isinstance(gamePacket,GameInitPacket):
                    print("1")
                    print(process_game_init(gamePacket))
                    print("Game started")
                    gameRequirePacket = create_game_require_pay_packet('9821389123',"ymao22_account",5)
                    self.transport.write(gameRequirePacket.__serialize__())
                    print("Game started new")
                elif isinstance(gamePacket,GamePayPacket):
                     receipt, receipt_sig = process_game_pay_packet(gamePacket)
                     print(receipt)
                     print(receipt_sig)
                     self.game = escape_room_006.EscapeRoomGame(output = self.send)
                     self.game.create_game()
                     self.game.start()
                     self.loop = asyncio.get_event_loop()
                     self.loop.create_task(self.flyingkey_event())

           # data_send = self.game.command(command[0])
        def send(self, data):
            gameBackPacket = create_game_response(data,self.game.status)
            print(gameBackPacket.response)
            self.transport.write(gameBackPacket.__serialize__())
            time.sleep(0.25)
        async def flyingkey_event(self):
            await asyncio.wait([asyncio.ensure_future(a) for a in self.game.agents]) 
if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        EnablePresetLogging(PRESET_DEBUG)
        coro = playground.create_server(EchoServer,'localhost',21005)
        server = loop.run_until_complete(coro)
         
        try:
	        loop.run_forever()
        except KeyboardInterrupt:
                pass
        server.close()
        loop.run_until_complete(server.wait_close())
        loop.close()




