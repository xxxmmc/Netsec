import asyncio
import time
import playground
class EchoClient(asyncio.Protocol):
	def __init__(self):
            self.good_list = ["look","look mirror","get hairpin","unlock chest with hairpin","open chest","get hammer from chest","unlock door with hairpin","open door"]
            self.count = 0;
	def connection_made(self, transport):
            self.transport = transport
            #self.transport("<EOL>\n".encode())
            self.transport.write("RESULT,139972bb944d7ae8b9e7f7578ebaa1e8965a975d22f09fbcf41376f80780ef44".encode())
            time.sleep(0.25)
	def data_received(self, data):
            print(data.decode())
if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = playground.create_connection(EchoClient,'20194.0.0.19000',19005)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	client.close()
	loop.run_until_complete(client.close())
	loop.close()
