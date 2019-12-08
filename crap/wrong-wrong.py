from ..poop.protocol import POOP
from uuid import UUID
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import datetime
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

logger = logging.getLogger("playground.__connector__." + __name__)


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
        ("cert", BUFFER({Optional: True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]


class crap(StackingProtocol):
    def __init__(self, mode):
        logger.debug("Beginning")
        super().__init__()
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{}: connection begin".format(self.mode))
        self.transport = transport

        if self.mode == "client":
            nonce = 10

            self.client_private_key, self.data, self.RSA_private_key, client_signature, self.nonce_bytes = self.create_key(nonce)

            cert = self.create_cert(self.RSA_private_key)

            packet = HandshakePacket(status=0, pk=self.data, signature=client_signature, nonce=nonce, cert=cert)

            self.transport.write(packet.__serialize__())

    def data_received(self, buffer):
        logger.debug("{} receive".format(self.mode))
        self.deserializer.update(buffer)

        for packet in self.deserializer.nextPackets():
            if type(packet) == HandshakePacket:
                self.handshakepacket_received(packet)
                continue
            else:
                print("{} receive: {}".format(self.mode, type(packet)))
                return

    def create_key(self, nonce):
        # First Step: Create client's private key
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

        # Second Step: serialize
        data = private_key.public_key().public_bytes(Encoding.PEM,
                                                                 PublicFormat.SubjectPublicKeyInfo)

        # Third Step: create RSA key
        RSA_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                   backend=default_backend())

        # Fourth Step: Sign
        signature = RSA_private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                salt_length=padding.PSS.MAX_LENGTH),
                                         hashes.SHA256())

        # Fifth Step: nonce
        nonce_bytes = str(nonce).encode('ASCII')
        logger.debug("create key")
        return private_key, data, RSA_private_key, signature, nonce_bytes

    def create_cert(self, RSA_private_key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Bo Hui"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            self.RSA_private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=30)).sign(private_key=RSA_private_key,
                                                                           algorithm=hashes.SHA256(),
                                                                           backend=default_backend()).public_bytes(
            Encoding.PEM)
        return cert

    def handshakepacket_received(self, packet):
        if self.mode == "server":
            if packet.status == 0:
                cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
                self.extract_public_client_key = cert.public_key()

                try:
                    self.extract_public_client_key.verify(packet.signature, packet.pk,
                                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                      salt_length=padding.PSS.MAX_LENGTH),
                                                          hashes.SHA256())
                except:
                    logger.debug("Server 1: wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()

                nonce = 10

                self.server_private_key, self.data, self.RSA_private_key, server_signature, self.nonce_bytes = self.create_key(
                    nonce)


                # Reveive nonceA
                nonce_client = str(packet.nonce).encode('ASCII')

                cert = self.create_cert(self.RSA_private_key)

                nonce_signature_server = self.RSA_private_key.sign(nonce_client,
                                                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                               salt_length=padding.PSS.MAX_LENGTH),
                                                                   hashes.SHA256())
                packet = HandshakePacket(status=1, pk=self.data, signature=server_signature, nonce=nonce,
                                         nonceSignature=nonce_signature_server, cert=cert)

                self.transport.write(packet.__serialize__())
            elif packet.status == 1:
                try:
                    self.extract_public_client_key.verify(packet.nonceSignature, self.nonce_bytes,
                                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                      salt_length=padding.PSS.MAX_LENGTH),
                                                          hashes.SHA256())
                except Exception:
                    logger.debug("Server 2: wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()
                print("crap Handshake complete")
        if self.mode == "client" and packet.status == 1:
            cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
            self.extract_public_server_key = cert.public_key()

            try:
                self.extract_public_server_key.verify(packet.signature, packet.pk,
                                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                  salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())
                self.extract_public_server_key.verify(packet.nonceSignature, self.nonceA,
                                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                  salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())

            except Exception:
                logger.debug("client verify 1: wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            nonce_server = str(packet.nonce).encode('ASCII')

            nonce_signature_client = self.RSA_private_key.sign(nonce_server,
                                                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                           salt_length=padding.PSS.MAX_LENGTH),
                                                               hashes.SHA256())

            packet = HandshakePacket(status=1, nonceSignature=nonce_signature_client)
            self.transport.write(packet.__serialize__())


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: crap(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: crap(mode="server"))

