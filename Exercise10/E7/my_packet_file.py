from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, STRING, BUFFER, UINT16, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

class GameInitPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.GameInitPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("username", STRING)
    ]

class GameRequirePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.GameRequirePayPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("unique_id", STRING),
        ("account", STRING),
        ("amount", UINT16)
    ]

class GamePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.GamePayPacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("receipt", BUFFER),
        ("receipt_signature", BUFFER)
    ]

class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.command"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("command", STRING)
    ]
    
class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.response"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("response", STRING),
        ("status", STRING)
    ]

def create_game_init_packet(username):
    return GameInitPacket(username=username)

def process_game_init(pkt):
    return "wbai3"

def create_game_require_pay_packet(unique_id, account, amount):
    return GameRequirePayPacket(unique_id=unique_id, account=account, amount=amount)

def process_game_require_pay_packet(pkt):
    return pkt.unique_id, pkt.account, pkt.amount

def create_game_pay_packet(receipt, receipt_signature):
    return GamePayPacket(receipt=receipt, receipt_signature=receipt_signature)

def process_game_pay_packet(pkt):
    return pkt.receipt, pkt.receipt_signature

def create_game_response(response, status):
    return GameResponsePacket(response=response, status=status)

def process_game_response(pkt):
    return pkt.response, pkt.status

def create_game_command(command):
    return GameCommandPacket(command=command)

def process_game_command(pkt):
    return pkt.command

