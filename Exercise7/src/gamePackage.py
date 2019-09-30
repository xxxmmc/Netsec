from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import *# whatever field types you need

class GameInitPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameInitPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want
    FIELDS = [
        ("user_name",STRING),# whatever you want here
   
    ]
    # whatever you need to get the command for the game    
class GameRequirePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameRequirePayPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("id",STRING),# whatever you want here
        ("accountname",STRING),
        ("amountnum",INT16)
    ]

class GamePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGamePayPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("recpt",BUFFER),# whatever you want here
        ("recpt_sig",BUFFER),
    ]

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameCommandPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("command_line",STRING)# whatever you want here
    ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(command_line = s)# whatever arguments needed to construct the packet)
    
    def command(self):
        # MUST RETURN A STRING!
        return self.command_line# whatever you need to get the command for the game.
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameResponcePacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("stats",STRING),# whatever you want here
        ("resp",STRING)
    ]
    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls(resp = response, stats = status )# whatever you need to construct the packet 
    
    def game_over(self):
        # MUST RETURN A BOOL
        return self.stats != "playing"# whatever you need to do to determine if the game is over
    
    def status(self):
        # MUST RETURN game.status (as a string)
        return self.stats# whatever you need to do to return the status
    
    def response(self):
        # MUST return game response as a string
        return self.resp# whatever you need to do to return the response
def create_game_init_packet(username):
        return GameInitPacket(user_name=username)
def process_game_init(pkt):
        return "test7"
def create_game_require_pay_packet(unique_id, account, amount):
        #print("new")
        return GameRequirePayPacket(id = unique_id, accountname = account, amountnum = amount)# whatever you need to construct the packet
def process_game_require_pay_packet(pkt):
        # MUST RETURN A STRING!
        #print("new")
        return pkt.id,pkt.accountname,pkt.amountnum# whatever you need to get the command for the game.
def create_game_pay_packet(receipt, receipt_signature):
        # whatever arguments needed to construct the packet)
        return GamePayPacket(recpt = receipt, recpt_sig = receipt_signature)# whatever you need to construct the packet
def process_game_pay_packet(pkt):
        # MUST RETURN A STRING!
        return pkt.recpt,pkt.recpt_sig# whatever you need to get the command for the game.
def create_game_response(response, status):
        return GameResponsePacket(resp=response, stats=status)
def process_game_response(pkt):
        return pkt.resp, pkt.stats
def create_game_command(command):
        return GameCommandPacket(command_line=command)
def process_game_command(pkt):
        return pkt.command_line


