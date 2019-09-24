import asyncio
import escape_room_004
import playground
import gamePackage
class EchoServer(asyncio.Protocol):
        def __init__(self):
            pass 
        def connection_made(self, transport):
            print("connection made")
            self.transport = transport
            self.game = escape_room_004.EscapeRoomGame(output = self.data_send)
            self.game.create_game()
            self.game.start()
            self.loop = asyncio.get_event_loop()
            self.loop.create_task(self.flyingkey_event())
        def data_received(self, data):
            data = data.decode()
            command = list(filter(None, data.split("<EOL>\n")))
            for commandline in command:
                print('Data recevied:{!r}'.format(commandline))
                self.game.command(commandline)
           # data_send = self.game.command(command[0])
         def send(self, data):
            GameCommandPacket = gamePackage.GameCommandPacket(command = data)
            print('Data sent:{!r}'.format(data))  
            self.transport.write(GameCommandPacket.__serialize__())
        async def flyingkey_event(self):
            await asyncio.wait([asyncio.ensure_future(a) for a in self.game.agents]) 
if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_server(EchoServer,'localhost',30000)
	server = loop.run_until_complete(coro)
         
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	server.close()
	loop.run_until_complete(server.wait_close())
	loop.close()

