import asyncio
import time
import playground
from playground.common.logging import EnablePresetLogging,PRESET_DEBUG
class EchoClient(asyncio.Protocol):
	def __init__(self):
            self.good_list = ["look mirror","get hairpin","unlock chest with hairpin","open chest","get hammer in chest"]
            self.good_list2 = [" ","get key","unlock door with key","open door"]
            self.count = 0;
            self.flag = 0;
            self.hitflag = 0;
            self.count2 = 0;
           # EnablePresetLogging(PRESET_DEBUG)
	def connection_made(self, transport):
            self.transport = transport
            self.transport.write("<EOL>\n".encode())
           # print("good")
           # self.transport.write("<EOL>\n".encode())
           # print("night")
            self.transport.write("SUBMIT,Yu Mao,ymao@jh.edu,5,30000".encode())
            time.sleep(0.25)
	def data_received(self, data):
           # print("mmy")
            print(data.decode().split())
            if self.count < 5:
                self.transport.write(self.good_list[self.count].encode())
                time.sleep(0.25)
                self.count += 1
                print(self.count)
            elif self.count == 5 and data.decode().split()[-1] == 'wall<EOL>':
                self.transport.write("hit flyingkey with hammer".encode())
                self.count += 1;
                print("good")
                time.sleep(0.25)
            elif self.count > 5:
                if self.count2 < 4:
                    self.transport.write(self.good_list2[self.count2].encode())
                    self.count2 += 1
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
