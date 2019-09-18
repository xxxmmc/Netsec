import asyncio
import escape_room_004
import playground
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
        def data_send(self, data):
            self.transport.write((data+'<EOL>\n').encode())
            print('Data sent:{!r}'.format(data))  
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
