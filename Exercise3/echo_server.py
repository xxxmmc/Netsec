import asyncio
import MAO_game
class EchoServer(asyncio.Protocol):
        def __init__(self):
            pass 
        def connection_made(self, transport):
            print("connection made")
            self.transport = transport
            self.game = MAO_game.EscapeRoomGame(output = self.data_send)
            self.game.create_game()
            self.game.start()

        def data_received(self, data):
            data = data.decode()
            command = list(filter(None, data.split("<EOL>\n")))
            for commandline in command:
                print('Data recevied:{!r}'.format(commandline))
                self.game.command(commandline)
        def data_send(self, data):
            self.transport.write((data+'<EOL>\n').encode())
            print('Data sent:{!r}'.format(data))  
    
if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_server(EchoServer,'',30000)
	server = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	server.close()
	loop.run_until_complete(server.wait_close())
	loop.close()
