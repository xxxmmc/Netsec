from ..poop.protocol import POOP
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import time
import datetime
import asyncio
import binascii
import bisect
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID


logger = logging.getLogger("playground.__crap__." + __name__)


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

class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} CRAP: init protocol".format(mode))
        super().__init__()
        self._mode = mode
        self.client_private_key = None
        self.client_public_key = None
        self.client_sign_pvk = None
        self.client_sign_pbk = None
        self.server_private_key = None
        self.server_public_key = None
        self.server_sign_pvk = None
        self.server_sign_pbk = None
        self.cnonce = 0
        self.snonce = 0
        self.deserializer = CrapPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{} CRAP: connection made".format(self._mode))
        self.transport = transport
        if self._mode == "client":
            self.client_private_key= ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.client_public_key = self.client_private_key.public_key()
            self.client_sign_pvk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.client_sign_pbk = self.client_sign_pvk.public_key()
            #self.nonce = randrange(2147483647)
            self.cnonce = randrange(255)
            self.serialized_cnonce = str(self.cnonce).encode('ASCII')
            data = self.client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            sigA = self.client_sign_pvk.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            tls_handshake_packet = HandshakePacket(status=0)
            tls_handshake_packet.pk = data
            tls_handshake_packet.signature = sigA
            tls_handshake_packet.nonce = self.cnonce

            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'team5_client'),]))
            builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'team5_client'),]))
            builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=30))
            builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=30))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(self.client_sign_pbk)
            certificate = builder.sign(private_key = self.client_sign_pvk, algorithm = hashes.SHA256(),backend = default_backend())
            client_cert = certificate.public_bytes(Encoding.PEM)
            tls_handshake_packet.cert = client_cert
            self.transport.write(tls_handshake_packet.__serialize__())
            print("CLIENT:11111111111111111111111111111111111111")
            logger.debug("Client send TLS handshake!")





    def data_received(self, buffer):
        logger.debug("{} POOP recv a buffer of size {}".format(self._mode, len(buffer)))
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            if pkt.DEFINITION_IDENTIFIER == "crap.handshakepacket":
                if self._mode == "server":
                    if pkt.status == 0:
                        certification = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                        self.cert_pubkA = certification.public_key()
                        print("222222222222222222222")
                        try:
                            self.cert_pubkA.verify(pkt.signature, pkt.pk,
                                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                        except Exception as error:
                            logger.debug("Server verify cert fail!")
                            tls_handshake_packet = HandshakePacket(status=2)
                            self.transport.write(tls_handshake_packet.__serialize__())
                            self.transport.close()

                        logger.debug("Server verify cert success!")
                        self.server_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                        self.server_public_key = self.server_private_key.public_key()
                        self.server_sign_pvk = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                                        backend=default_backend())
                        self.server_sign_pbk = self.server_sign_pvk.public_key()
                        self.snonce = randrange(255)
                        self.serialized_snonce = str(self.snonce).encode('ASCII')
                        self.serialized_cnonce = str(pkt.nonce).encode('ASCII')
                        print("55555555555555555555555555")
                        data = self.server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        sigB = self.server_sign_pvk.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                        print("777777777777777777777777")
                        tls_handshake_packet = HandshakePacket(status=1)
                        tls_handshake_packet.pk = data
                        tls_handshake_packet.signature = sigB
                        tls_handshake_packet.nonce = self.snonce
                        print("666666666666666666666666666666666666")
                        builder = x509.CertificateBuilder()
                        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'team5_server'), ]))
                        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'team5_server'), ]))
                        builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=30))
                        builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=30))
                        builder = builder.serial_number(x509.random_serial_number())
                        builder = builder.public_key(self.server_sign_pbk)
                        certificate = builder.sign(private_key=self.server_sign_pvk, algorithm=hashes.SHA256(),
                                                   backend=default_backend())
                        server_cert = certificate.public_bytes(Encoding.PEM)
                        tls_handshake_packet.cert = server_cert
                        cnonceSignature = self.server_sign_pvk.sign(self.serialized_cnonce,
                                                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                       salt_length=padding.PSS.MAX_LENGTH),
                                                           hashes.SHA256())
                        print("1231313131313131")
                        tls_handshake_packet.nonceSignature = cnonceSignature
                        self.transport.write(tls_handshake_packet.__serialize__())
                        logger.debug("Client send TLS handshake!")

                    elif pkt.status == 1:
                        try:
                            self.cert_pubkA.verify(packet.nonceSignature, self.serialized_snonce,
                                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                  salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())

                        except Exception as error:
                            logger.debug("Server verify failed because wrong signature")
                            tls_handshake_packet = HandshakePacket(status=2)
                            self.transport.write(tls_handshake_packet.__serialize__())
                            self.transport.close()
                        print("TLS Handshake complete")



                elif self._mode == "client" and pkt.status == 1:
                    certification = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                    self.cert_pubkB = certification.public_key()
                    try:
                        self.cert_pubkB.verify(pkt.signature, pkt.pk,
                                             padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                         salt_length=padding.PSS.MAX_LENGTH),
                                             hashes.SHA256())
                        self.cert_pubkB.verify(pkt.nonceSignature, self.serialized_cnonce,
                                             padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                         salt_length=padding.PSS.MAX_LENGTH),
                                             hashes.SHA256())

                    except Exception as error:
                        logger.debug("client verify failed because wrong signature")
                        tls_handshake_packet = HandshakePacket(status=2)
                        self.transport.write(tls_handshake_packet.__serialize__())
                        self.transport.close()

                    # Generate shared key
                    # pubkA_recv = load_pem_public_key(packet.pk, backend=default_backend())
                    # client_shared_key = privkB.exchange(ec.ECDH, pubkA_recv)

                    # Reveive nonceB
                    self.serialized_snonce = str(pkt.nonce).encode('ASCII')

                    snonceSignature = self.client_sign_pvk.sign(self.serialized_snonce,
                                                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                   salt_length=padding.PSS.MAX_LENGTH),
                                                       hashes.SHA256())

                    tls_handshake_packet = HandshakePacket(status=1, nonceSignature=snonceSignature)
                    self.transport.write(tls_handshake_packet.__serialize__())







SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),lambda: CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),lambda: CRAP(mode="server"))
