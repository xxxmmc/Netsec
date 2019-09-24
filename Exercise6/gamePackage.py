from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import *# whatever field types you need

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
        return cls(reps = response, stats = status )# whatever you need to construct the packet )
    
    def game_over(self):
        # MUST RETURN A BOOL
        return self.stats != "playing"# whatever you need to do to determine if the game is over
    
    def status(self):
        # MUST RETURN game.status (as a string)
        return self.stats# whatever you need to do to return the status
    
    def response(self):
        # MUST return game response as a string
        return self.reps# whatever you need to do to return the response
