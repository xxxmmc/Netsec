from ..poop.protocol import POOP
from uuid import UUID
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import datetime
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import binascii
import bisect

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
        ("cert", BUFFER({Optional: True})),
        ("certChain", LIST(BUFFER, {Optional: True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER)
    ]


class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket”"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("message", STRING),
    ]


class CRAPTransport(StackingTransport):

    def connect_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        self.protocol.data_send(data)

    def close(self):
        self.protocol.transport.close()

class CRAP(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode
        self.crap_status = None
        self.Desrialize_Packet = CrapPacketType.Deserializer()
        self.subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Bo Hui"),
                             x509.NameAttribute(NameOID.COMMON_NAME, u"20194.5.20.30"),
                             ])

    def GenerateTeamCert(self):
        cert_team5 = open("team5_signed.cert", 'rb').read()
        private_key_team5_rd = open("private_key.pem", 'rb').read()
        cert_team5_pem = x509.load_pem_x509_certificate(cert_team5, default_backend())
        private_key_team5_pem = load_pem_private_key(private_key_team5_rd,
                                                    password=None,
                                                    backend=default_backend())
        return cert_team5, cert_team5_pem, private_key_team5_pem


    def hash_value(self):
        digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest1.update(self.shared_key)
        hash1 = digest1.finalize()
        ivA = hash1[0:12]
        ivB = hash1[12:24]

        digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest2.update(hash1)
        hash2 = digest2.finalize()
        EncA = hash2[0:16]

        digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest3.update(hash2)
        hash3 = digest3.finalize()
        DecA = hash3[0:16]

        return ivA, ivB, EncA, DecA

    def enc_data_send(self, enc, iv, data):
        aesgcm = AESGCM(enc)
        encData = aesgcm.encrypt(iv, data, None)
        new_packet = DataPacket(data=encData)
        self.transport.write(new_packet.__serialize__())
        print("{} send encrypted data".format(self.mode))

    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self.mode))
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)

        if self.mode == "client":
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            self.dataA = self.privkA.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

            team5_cert_data, self.team5_cert, self.team5_privk = self.GenerateTeamCert()

            certificate = x509.CertificateBuilder().subject_name(self.subject).issuer_name(self.team5_cert.subject).public_key(self.signkA.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30)).sign(private_key=self.team5_privk,algorithm=hashes.SHA256(),backend=default_backend())

            certA = certificate.public_bytes(Encoding.PEM)

            self.cert_chain = [team5_cert_data]

            # Create signature
            sigA = self.signkA.sign(self.dataA,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

            # Create nonceA
            tmp_nonceA = randrange(0, 1000)
            self.nonceA = str(tmp_nonceA).encode('ASCII')

            # Generate packet
            new_secure_packet = HandshakePacket(status=0, pk=self.dataA, signature=sigA, nonce=tmp_nonceA, cert=certA,
                                                certChain=self.cert_chain)
            self.transport.write(new_secure_packet.__serialize__())


    def data_received(self, buffer):
        self.Desrialize_Packet.update(buffer)
        packet_recieve = self.Desrialize_Packet.nextPackets()

        for pkt in packet_recieve:
            packet_type = pkt.DEFINITION_IDENTIFIER
            if not packet_type:
                print("{} Crap error: the recv pkt don't have a DEFINITION_IDENTIFIER")
                return
            logger.debug("{} Crap the pkt name is: {}".format(self.mode, packet_type))

            if packet_type == "crap.handshakepacket":
                if self.crap_status == "ESTABLISHED":
                    logger.debug("recvive a handshake packet when connect ESTABLISHED")
                    return
                else:
                    if self.mode == "server":
                        self.server_crap_handshake_recv(pkt)
                    if self.mode == "clent":
                        self.client_crap_handshake_recv(pkt)

            elif packet_type == "crap.datapacket":
                if self.mode == "server":
                    self.crap_data_recv(pkt, self.ivA)
                    self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
                if self.mode == "clent":
                    self.crap_data_recv(pkt, self.ivB)
                    self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")

            elif packet_type == "crap.errorpacket":
                logger.debug("Error packet received received from {}".format(self.mode))
                self.crap_errer_recv(pkt)

            else:
                print("{} Crap error: the recv pkt name: \"{}\" this is unexpected".format(
                    self.mode, packet_type))
                return

    def server_crap_handshake_recv(self, packet):
        if packet.status == 0:

            team5_cert_data, self.team5_cert, self.team5_privk = self.GenerateTeamCert()

            certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
            self.extract_pubkA = certification.public_key()

            try:
                self.extract_pubkA.verify(packet.signature, packet.pk,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                team5_addr = self.team5_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                recv_addr = certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                print("team5 address:", team5_addr)
            except Exception as error:
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            self.privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            self.dataB = self.privkB.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

            recv_pubk = load_pem_public_key(packet.pk, backend=default_backend())
            self.shared_key = self.privkB.exchange(ec.ECDH(), recv_pubk)

            certificate = x509.CertificateBuilder().subject_name(self.subject).issuer_name(self.team5_cert.subject).public_key(self.signkB.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30)).sign(private_key=self.team5_privk,algorithm=hashes.SHA256(),backend=default_backend())

            certB = certificate.public_bytes(Encoding.PEM)

            self.cert_chain = [team5_cert_data]

            sigB = self.signkB.sign(self.dataB, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

            tmp_nonceB = randrange(0, 1000)
            self.nonceB = str(tmp_nonceB).encode('ASCII')

            nonceA = str(packet.nonce).encode('ASCII')

            nonceSignatureB = self.signkB.sign(nonceA,
                                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH),
                                               hashes.SHA256())

            packet = HandshakePacket(status=1, pk=self.dataB, signature=sigB, nonce=tmp_nonceB,
                                                nonceSignature=nonceSignatureB, cert=certB,
                                                certChain=self.cert_chain)

            self.transport.write(packet.__serialize__())

        elif packet.status == 1:
            try:
                self.extract_pubkA.verify(packet.nonceSignature, self.nonceB,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          hashes.SHA256())

            except Exception:
                logger.debug("{} verify failed because wrong signature".format(self.mode))
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            self.ivA, self.ivB, self.decB, self.encB = self.hash_value()
            self.crap_status = "ESTABLISHED"
            self.higherProtocol().connection_made(self.higher_transport)

    def client_crap_handshake_recv(self, packet):
        if packet.status == 1:
            certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
            extract_pubkB = certification.public_key()
            try:
                extract_pubkB.verify(packet.signature, packet.pk,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
                extract_pubkB.verify(packet.nonceSignature, self.nonceA,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())

            except Exception:
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            recv_pubk = load_pem_public_key(packet.pk, backend=default_backend())
            self.shared_key = self.privkA.exchange(ec.ECDH(), recv_pubk)

            nonceB = str(packet.nonce).encode('ASCII')

            nonceSignatureA = self.signkA.sign(nonceB,
                                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH),
                                               hashes.SHA256())

            new_secure_packet = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
            self.transport.write(new_secure_packet.__serialize__())

            self.ivA, self.ivB, self.encA, self.decA = self.Hash()

            self.crap_status = "ESTABLISHED"
            self.higherProtocol().connection_made(self.higher_transport)

        else:
            packet = HandshakePacket(status=2)
            self.transport.write(packet.__serialize__())
            self.transport.close()

    def data_send(self, data):
        if self.mode == "client":
            self.enc_data_send(self.encA, self.ivA, data)
            self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")

        if self.mode == "server":
            self.enc_data_send(self.encB, self.ivB, data)
            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")


    def crap_data_recv(self, packet, iv):
        aesgcm = AESGCM(self.decB)
        try:
            decData = aesgcm.decrypt(iv, packet.data, None)

        except Exception:
            logger.debug("{} Decryption failed".format(self.mode))
        #iv = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
        self.higherProtocol().data_received(decData)




SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"), lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"), lambda: CRAP(mode="server"))

