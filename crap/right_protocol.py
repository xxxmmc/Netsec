
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID

import binascii
import bisect

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
        ("cert", BUFFER({Optional: True}))
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
        self.datasentA = None
        self.datasentB = None
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self.mode))
        self.transport = transport
        print("connection_made")
        if self.mode == "client":
            # Using 
            self.privatekeyA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkA = self.privatekeyA.public_key()
            #save original pubkA
            publickA = pubkA; 
            # Create pk in packet (serialization)
            pubkA = pubkA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.datasentA = pubkA

            # Create long term key for signing
            self.signaturekA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.pubk_sign_A = self.signaturekA.public_key()

            # Create signature
            sign_A = self.signaturekA.sign(self.datasentA,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

            # Create nonceA
            nonceA = 1
            self.nonceA = str(nonceA).encode('ASCII')

            # Create certificate with the help of ephemeral private key
            subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MarryLand"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 5"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Yu Mao"),
            ])
            certificate = x509.CertificateBuilder().subject_name(
            subject
            ).issuer_name(
            issuer
            ).public_key(
            self.signaturekA.public_key()
            ).serial_number(
            x509.random_serial_number()
            ).not_valid_before(
            datetime.datetime.utcnow()
            ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
            ).sign(self.signaturekA, hashes.SHA256(), default_backend())

      # Create CertA to transmit (serialization)
            certA = certificate.public_bytes(Encoding.PEM)
            #print(self.pubk_sign_A.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

            new_secure_packet = HandshakePacket(status=0, pk=self.datasentA, signature=sign_A, nonce=nonceA, cert=certA)
            self.transport.write(new_secure_packet.__serialize__())

    def data_received(self, buffer):
        logger.debug("{} Crap recv a buffer of size {}".format(self.mode, len(buffer)))
        self.deserializer.update(buffer)

        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if not pkt_type:  # NOTE: not sure if this is necessary
                print("{} Crap error: the recv pkt don't have a DEFINITION_IDENTIFIER")
                return
            logger.debug("{} Crap the pkt name is: {}".format(self.mode, pkt_type))
            if pkt_type == "crap.handshakepacket":
                self.crap_handshake_recv(pkt)
                continue
            else:
                print("{} Crap error: the recv pkt name: \"{}\" this is unexpected".format(
                    self.mode, pkt_type))
                return

    def crap_handshake_recv(self, packet):
        if self.mode == "server" and packet.status == 0:
                certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
                self.get_pubKA = certification.public_key()
                # print(self.get_pubKA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

                try:
                    self.get_pubKA.verify(packet.signature, packet.pk,
                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                except Exception as error:
                    logger.debug("wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()

                # Create Server long term key
                privatekeyB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                pubkB = privatekeyB.public_key()
                publickB = pubkB
                # Create pk in packet (serialization)
                tmp_pubkB = pubkB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.datasentB = tmp_pubkB

                # Create ephemeral key for signing
                self.signaturekB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                self.pubk_sign_B = self.signaturekB.public_key()

                # Create signature
                sign_B = self.signaturekB.sign(self.datasentB,
                                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                    salt_length=padding.PSS.MAX_LENGTH),
                                        hashes.SHA256())

                # Create nonceB
                tmp_nonceB = 1
                self.nonceB = str(tmp_nonceB).encode('ASCII')

                # Reveive nonceA
                nonceA = str(packet.nonce).encode('ASCII')

                # Generate shared key
                # pubkB_recv = load_pem_public_key(packet.pk, backend=default_backend())
                # server_shared_key = privatekeyB.exchange(ec.ECDH, pubkB_recv)

                # Create certificate with the help of ephemeral private key
                subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MarryLand"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Peskvile"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 5"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"Yu Mao"),
                ])
                certificate = x509.CertificateBuilder().subject_name(
                subject
                ).issuer_name(
                issuer
                ).public_key(
                self.signaturekB.public_key()
                ).serial_number(
                x509.random_serial_number()
                ).not_valid_before(
                datetime.datetime.utcnow()
                ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
                ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
                # Sign our certificate with our private key
                ).sign(self.signaturekB, hashes.SHA256(), default_backend())

                # Create CertB to transmit (serialization)
                
                
                
                
                
                certB = certificate.public_bytes(Encoding.PEM)

                # Create nonceSignatureB (bytes)

                nonceSignatureB = self.signaturekB.sign(nonceA,
                                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                               salt_length=padding.PSS.MAX_LENGTH),
                                                   hashes.SHA256())

                new_secure_packet = HandshakePacket(status=1, pk=self.datasentB, signature=sign_B, nonce=tmp_nonceB,
                                                    nonceSignature=nonceSignatureB, cert=certB)

                self.transport.write(new_secure_packet.__serialize__())

        elif self.mode == "server" and packet.status == 1:
                try:
                    self.get_pubKA.verify(packet.nonceSignature, self.nonceB,
                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH),
                                              hashes.SHA256())

                except Exception as error:
                    logger.debug("Server verify failed because wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()
                print("Handshake complete")

        if self.mode == "client" and packet.status == 1:
            certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
            extract_pubkB = certification.public_key()
            try:
                extract_pubkB.verify(packet.signature, packet.pk,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
                extract_pubkB.verify(packet.nonceSignature, self.nonceA,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())

            except Exception as error:
                logger.debug("client verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            # Generate shared key
            #pubkA_recv = load_pem_public_key(packet.pk, backend=default_backend())
            #client_shared_key = privatekeyB.exchange(ec.ECDH, pubkA_recv)

            # Reveive nonceB
            nonceB = str(packet.nonce).encode('ASCII')

            nonceSignatureA = self.signaturekA.sign(nonceB,
                                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH),
                                               hashes.SHA256())

            new_secure_packet = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
            self.transport.write(new_secure_packet.__serialize__())


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: CRAP(mode="server"))
