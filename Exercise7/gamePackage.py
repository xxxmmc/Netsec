from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import *# whatever field types you need

class GameInitPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameInitPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want
    FIELDS = [
        ("yourname",STRING),# whatever you want here
        ("signal",STRING)#mark the beginning of the game
    ]
    @classmethod
    def create_game_init_packet(cls, s):
        return cls(yourname = "test",signal="begin")
    def process_game_init(pkt):
        try:
            return pkt.yourname 
        except Exception as e:
            print('Error',e)
    # whatever you need to get the command for the game    
class GameRequirePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameRequirePayPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("id",STRING),# whatever you want here
        ("accountname",STRING),
        ("amountnum",INT16)
    ]
    @classmethod
    def create_game_require_pay_packet(cls,unique_id, account, amount):
        return cls(id = unique_id, accountname = account, amountnum = amount)# whatever you need to construct the packet
    def process_game_require_pay_packet(self):
        # MUST RETURN A STRING!
        return self.id,self.accountname,self.amount# whatever you need to get the command for the game.
    def check_game_require_pay_packet(self):
        return amount <= 10
class GamePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGamePayPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("recpt",STRING),# whatever you want here
        ("recpt_sig",STRING),
    ]
    @classmethod
    def create_game_pay_packet(receipt, receipt_signature):
        # whatever arguments needed to construct the packet)
        return cls(recpt = receipt, recpt_sig = receipt_signature)# whatever you need to construct the packet
    def process_game_pay_packet(self):
        # MUST RETURN A STRING!
        return self.recpt,self.recpt_sig# whatever you need to get the command for the game.
        
        
class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameCommandPacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("command",STRING)# whatever you want here
    ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(command = s)# whatever arguments needed to construct the packet)
    
    def command(self):
        # MUST RETURN A STRING!
        return self.command# whatever you need to get the command for the game.
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "testGameResponcePacket"# whatever you want
    DEFINITION_VERSION = "1.0"# whatever you want

    FIELDS = [
        ("stats",STRING),# whatever you want here
        ("reps",STRING)
    ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls(reps = response, stats = status )# whatever you need to construct the packet 
    
    def game_over(self):
        # MUST RETURN A BOOL
        return self.stats != "playing"# whatever you need to do to determine if the game is over
    
    def status(self):
        # MUST RETURN game.status (as a string)
        return self.stats# whatever you need to do to return the status
    
    def response(self):
        # MUST return game response as a string
        return self.reps# whatever you need to do to return the response

