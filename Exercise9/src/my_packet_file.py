from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import *  # whatever field types you need

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise6.command"  # whatever you want
    DEFINITION_VERSION = "1.0" # whatever you want

    FIELDS = [
        ("comm", STRING)
        # whatever you want here
    ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(comm = s)# whatever arguments needed to construct the packet)

    def command(self):
        return(self.comm) # whatever you need to get the command for the game

class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise6.response" # whatever you want
    DEFINITION_VERSION = "1.0" # whatever you want

    FIELDS = [
        ("res", STRING),
        ("sta", STRING)
        # whatever you want here
    ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls(res = response, sta = status) # whatever you need to construct the packet )

    def game_over(self):
        return(self.status() != "playing")# whatever you need to do to determine if the game is over

    def status(self):
        return(self.sta)  # whatever you need to do to return the status

    def response(self):
        return(self.res) # whatever you need to do to return the response

class GameInitRequestPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise7.gameinit" # whatever you want
    DEFINITION_VERSION = "1.0" # whatever you want
    
    FIELDS = [
        ("username_string", STRING)
    ]



class GamePaymentRequestPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise7.gamepaymentrequest" # whatever you want
    DEFINITION_VERSION = "1.0" # whatever you want

    FIELDS = [
        ("unique_id", STRING),
        ("account", STRING),
        ("amount",UINT16)
    ]

class GamePaymentResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise7.gamepaymentresponse" # whatever you want
    DEFINITION_VERSION = "1.0" # whatever you want

    FIELDS = [
        ("receipt", BUFFER),
        ("receipt_sig", BUFFER)
    ]

def create_game_init_packet(username):
    return GameInitRequestPacket(username_string=username)
    
def process_game_init(pkt):
    return "Haoran"


def create_game_require_pay_packet(unique_id, account, amount):
    return GamePaymentRequestPacket(unique_id=unique_id, account=account, amount=amount)

def process_game_require_pay_packet(pkt):
    return (pkt.unique_id, pkt.account, pkt.amount)

def create_game_pay_packet(receipt, receipt_signature):
    return GamePaymentResponsePacket(receipt=receipt, receippt_sig=receipt_signature)

def process_game_pay_packet(pkt):
    return (pkt.receipt, pkt.receipt_sig)

def create_game_response(response, status):
    return GameResponsePacket(res=response, sta=status)

def process_game_response(pkt):
    return pkt.res

def create_game_command(command):
    return GameCommandPacket(cmmd=command)

def process_game_command(pkt):
    return pkt.comm





