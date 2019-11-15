from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import binascii
import bisect
from ..poop.protocol import POOP 
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
logger = logging.getLogger("playground.__connector__." + __name__)


# ------------------------------------------Crap Packet Definition Here
class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"


class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional: True})),
        ("nonceSignature", BUFFER({Optional: True})),
        ("signature", BUFFER({Optional: True})),
        ("pk", BUFFER({Optional: True})),
        ("cert", BUFFER({Optional:True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]


# ------------------------------------------Secure Protocol
class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.dataA = None
        self.dataB = None
        self.mode = mode
        self.nonceA = None
        self.nonceB = None
        self.nonceSignatureA = None
        self.nonceSignatureB = None
    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self.mode))
        self.transport = transport
        print("connection made")
        if self.mode == "client":
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkA = self.privkA.public_key()
            print("good")
            signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            print("signkA")
            pubk_sigA = signkA.public_key()
            
            # Various details about who we are. For a self-signed certificate the
            # subject and issuer are always the same.
            subject = issuer = x509.Name([
             x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
             x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Marryland"),
             x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 5"),
             x509.NameAttribute(NameOID.COMMON_NAME, u"Yu Mao"),
            ])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(signkA.public_key()).serial_number(
             x509.random_serial_number() ).not_valid_before(
             datetime.datetime.utcnow()
            ).not_valid_after(
             # Our certificate will be valid for 10 days
             datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
             x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
             critical=False,
            # Sign our certificate with our private key
            ).sign(signkA, hashes.SHA256(), default_backend())
            # Write our certificate out to disk.
           # with open("path/to/certificate.pem", "wb") as f:
         #       f.write(cert.public_bytes(serialization.Encoding.PEM))
            print("certificate")
            certA = cert.public_bytes(serialization.Encoding.PEM)
            self.dataA = pubkA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            print("wode public key =?")
            print(pubkA)
            self.nonceA = randrange(2**32)
            # sigA = signkA.sign(data,ec.ECDSA(hashes.SHA256()))
            print(self.nonceA)   
            sigA = signkA.sign(self.dataA, padding.PSS(mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
            print("qianwanle")
            new_secure_packet = HandshakePacket(status=0, pk=self.dataA, signature=sigA, cert=certA,nonce=self.nonceA)
            print("chudong")
            self.transport.write(new_secure_packet.__serialize__())

    def data_received(self, buffer):
        logger.debug("{} Crap recv a buffer of size {}".format(self.mode, len(buffer)))
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if not pkt_type:  # NOTE: not sure if this is necessary
                print("{} Crap error: the recv pkt don't have a DEFINITION_IDENTIFIER")
                return
            logger.debug("{} POOP the pkt name is: {}".format(self.mode, pkt_type))
            if pkt_type == "carp.handshakepacket":
                self.crap_handshake_recv(pkt)
                continue

    def crap_handshake_recv(self, packet):
        if self.mode == "server" and packet.status == 0:

            try:
                packet.cert.verify(packet.signature, self.dataA, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            except Exception as error:
                logger.debug("Sever verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkB = privkB.public_key()
            server_shared_key = privkB.exchange(ec.ECDH, packet.pk)

            signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            



            #pubk_sigB = signkB.public_key()

            #certB = pubk_sigB
            # Various details about who we are. For a self-signed certificate the
            # subject and issuer are always the same.
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Marryland"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Johns Hopkins"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 5"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"Mao Yu"),
            ])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                signkB.public_key()).serial_number(
                x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
                # Sign our certificate with our private key
            ).sign(signkB, hashes.SHA256(), default_backend())
            # Write our certificate out to disk.
            # with open("path/to/certificate.pem", "wb") as f:
            #       f.write(cert.public_bytes(serialization.Encoding.PEM))
            certB = cert.public_bytes(serialization.Encoding.PEM)
            self.nonceB = randrange(2 ** 32)

            self.dataB = pubkB
            sigB = signkB.sign(self.dataB, padding.PSS(mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
            self.nonceSignatureB = signkB.sign(self.nonceB, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            new_secure_packet = HandshakePacket(status=1, pk=pubkB, signature=sigB, cert=certB,nonce=self.nonceB,nonceSignature=self.nonceSignatureB)
            self.transport.write(new_secure_packet.__serialize__())

        if self.mode == "client" and packet.status == 1:
            try:
                packet.cert.verify(packet.signature, self.dataB, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

            except Exception as error:
                logger.debug("Sever verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            client_shared_key = self.privkA.exchange(ec.ECDH, packet.pk)
            new_secure_packet = HandshakePacket(status=1)
            self.transport.write(new_secure_packet.__serialize__())


#SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: CRAP(mode="client"),)

#SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: CRAP(mode="server"))

SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),lambda: CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),lambda: CRAP(mode="server"))

