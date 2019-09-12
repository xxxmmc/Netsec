import asyncio
import time
class EchoClient(asyncio.Protocol):
	def __init__(self):
            self.good_list = ["look","look mirror","get hairpin","unlock chest with hairpin","open chest","get hammer from chest","unlock door with hairpin","open door"]
            self.count = 0;
	def connection_made(self, transport):
            self.transport = transport
            self.transport.write("RESULT,b458b4dc397ec7da4a8a718ee1c381825bdbd4f0a52870ae453134994d0d935b".encode())
            time.sleep(0.25)
	def data_received(self, data):
            print(data.decode())
if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_connection(EchoClient,'192.168.200.52',19003)
	client = loop.run_until_complete(coro)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	client.close()
	loop.run_until_complete(client.close())
	loop.close()
