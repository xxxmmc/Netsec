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
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
        ("cert", BUFFER({Optional: True})),
        ("certChain", LIST(BUFFER, {Optional: True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
    ]


class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("message", STRING)
    ]


class CrapTransport(StackingTransport):
    def set_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        if self.mode == "client":
            aesgcm = AESGCM(self.encA)
            encDataA = aesgcm.encrypt(self.ivA, data, None)
            self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
            new_packet = DataPacket(data=encDataA)
            self.transport.write(new_packet.__serialize__())
            print("Client send encrypted data")

        if self.mode == "server":
            aesgcm = AESGCM(self.encB)
            encDataB = aesgcm.encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")
            new_packet = DataPacket(data=encDataB)
            self.transport.write(new_packet.__serialize__())
            print("server send encrypted data")

    def close(self):
        self.protocol.transport.close()


class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("************{} side crap __init__() **********".format(mode))
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
        self.crap_transport = CrapTransport(self.transport)
        self.crap_transport.set_protocol(self)

        if self._mode == "client":
            self.client_private_key= ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.client_public_key = self.client_private_key.public_key()
            self.client_sign_pvk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.client_sign_pbk = self.client_sign_pvk.public_key()
            root_CA_cert = open('20194_root.cert', 'rb').read()
            team5_CA_cert = open('team5_signed.cert', 'rb').read()
            team5_CA_private_key = open('private_key.pem', 'rb').read()
            self.team5_CA_sign_pvk = load_pem_private_key(team5_CA_private_key, password=None, backend=default_backend())
            self.root_CA_cert = x509.load_pem_x509_certificate(root_CA_cert, default_backend())
            self.team5_CA_cert = x509.load_pem_x509_certificate(team5_CA_cert, default_backend())
            self.team5_CA_sign_pbk = self.team5_CA_sign_pvk.public_key()
            self.root_CA_sign_pbk = self.root_CA_cert.public_key()

            print("load cert success!")

            self.cnonce = randrange(2 ** 32)
            self.serialized_cnonce = str(self.cnonce).encode('ASCII')

            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.5.20.30'), ]))
            builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.5.'), ]))
            builder = builder.not_valid_before(datetime.datetime.today() - (datetime.timedelta(days=90)))
            builder = builder.not_valid_after(datetime.datetime.today() + (datetime.timedelta(days=90)))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(self.client_sign_pbk)
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.5.20.30")]), critical=False)
            certificate = builder.sign(private_key=self.team5_CA_sign_pvk, algorithm=hashes.SHA256(),
                                       backend=default_backend())
            client_cert = certificate.public_bytes(Encoding.PEM)

            data = self.client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            sigA = self.client_sign_pvk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            tls_handshake_packet = HandshakePacket(status=0)
            tls_handshake_packet.pk = data
            tls_handshake_packet.signature = sigA
            tls_handshake_packet.nonce = self.cnonce
            tls_handshake_packet.cert = client_cert
            tls_handshake_packet.certChain = [team5_CA_cert]
            self.transport.write(tls_handshake_packet.__serialize__())
            logger.debug("Client send TLS handshake!")





    def data_received(self, buffer):
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, ErrorPacket):
                print("Receive an ErrorPacket from autograder!{}".format(pkt.message))
                return

            if pkt.DEFINITION_IDENTIFIER == "crap.handshakepacket":
                logger.debug("***{} CRAP: Received a TLS handshakepacket***".format(self._mode))
                if self._mode == "server":
                    root_CA_cert = open('20194_root.cert', 'rb').read()
                    team5_CA_cert = open('team5_signed.cert', 'rb').read()
                    team5_CA_private_key = open('private_key.pem', 'rb').read()

                    self.team5_CA_sign_pvk = load_pem_private_key(team5_CA_private_key, password=None,
                                                                  backend=default_backend())
                    self.root_CA_cert = x509.load_pem_x509_certificate(root_CA_cert, default_backend())
                    self.team5_CA_cert = x509.load_pem_x509_certificate(team5_CA_cert, default_backend())
                    self.team5_CA_sign_pbk = self.team5_CA_sign_pvk.public_key()
                    self.root_CA_sign_pbk = self.root_CA_cert.public_key()

                    if pkt.status == 0:
                        client_certification = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                        Upper_certification = x509.load_pem_x509_certificate(pkt.certChain[0], default_backend())

                        if(Upper_certification.issuer != self.root_CA_cert.issuer):
                            #Upper_certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                            print("Upper_cert is not signed by a trusted root CA!")
                            return

                        self.cert_pubkA = client_certification.public_key()
                        try:
                            self.cert_pubkA.verify(pkt.signature, pkt.pk,
                                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                        except Exception as error:
                            logger.debug("Server verify fails because DH public_key signature does not match")
                            tls_handshake_packet = HandshakePacket(status=2)
                            self.transport.write(tls_handshake_packet.__serialize__())
                            self.transport.close()



                        logger.debug("Server verify cert success")
                        self.server_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                        self.server_public_key = self.server_private_key.public_key()
                        self.server_sign_pvk = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                                        backend=default_backend())
                        self.server_sign_pbk = self.server_sign_pvk.public_key()
                        self.snonce = randrange(255)
                        self.serialized_snonce = str(self.snonce).encode('ASCII')
                        self.serialized_cnonce = str(pkt.nonce).encode('ASCII')

                        #generate shared_key
                        recv_pbk = load_pem_public_key(pkt.pk, backend=default_backend())
                        self.shared_key = self.server_private_key.exchange(ec.ECDH(), recv_pbk)

                        print("111111111111111111")
                        data = self.server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        sigB = self.server_sign_pvk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                        tls_handshake_packet = HandshakePacket(status=1)
                        tls_handshake_packet.pk = data
                        tls_handshake_packet.signature = sigB
                        tls_handshake_packet.nonce = self.snonce

                        print("12312313123123132")

                        builder = x509.CertificateBuilder()
                        builder = builder.subject_name(
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.5.20.30'), ]))
                        builder = builder.issuer_name(
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.5.'), ]))
                        builder = builder.not_valid_before(datetime.datetime.today() - (datetime.timedelta(days=90)))
                        builder = builder.not_valid_after(datetime.datetime.today() + (datetime.timedelta(days=90)))
                        builder = builder.serial_number(x509.random_serial_number())
                        builder = builder.public_key(self.server_sign_pbk)
                        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.5.20.30")]),
                                                        critical=False)
                        certificate = builder.sign(private_key=self.team5_CA_sign_pvk, algorithm=hashes.SHA256(),
                                                   backend=default_backend())
                        server_cert = certificate.public_bytes(Encoding.PEM)
                        print("Server get signed cert success!!!")

                        tls_handshake_packet.cert = server_cert
                        tls_handshake_packet.certChain = [team5_CA_cert]

                        cnonceSignature = self.server_sign_pvk.sign(self.serialized_cnonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                        tls_handshake_packet.nonceSignature = cnonceSignature

                        self.transport.write(tls_handshake_packet.__serialize__())
                        logger.debug("Server send TLS handshake!")

                    elif pkt.status == 1:
                        try:
                            self.cert_pubkA.verify(pkt.nonceSignature, self.serialized_snonce,
                                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                  salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())

                        except Exception as error:
                            logger.debug("server signature verify wrong: nonce")
                            tls_handshake_packet = HandshakePacket(status=2)
                            self.transport.write(tls_handshake_packet.__serialize__())
                            self.transport.close()
                        print("Server TLS Handshake complete")

                        # Create hash 1, IVA, IVB
                        digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        digest1.update(self.shared_key)
                        hash1 = digest1.finalize()
                        self.ivA = hash1[0:12]
                        self.ivB = hash1[12:24]
                        print("server iva:", self.ivA)
                        print("server ivb:", self.ivB)

                        # Create hash2, encA
                        digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        digest2.update(hash1)
                        hash2 = digest2.finalize()
                        self.decB = hash2[0:16]
                        print("server dec:", self.decB)

                        # Create hash3, decA
                        digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        digest3.update(hash2)
                        hash3 = digest3.finalize()
                        self.encB = hash3[0:16]
                        print("server enc:", self.encB)

                        self.higherProtocol().connection_made(self.crap_transport)



                elif self._mode == "client" and pkt.status == 1:
                    server_certification = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                    Upper_certification = x509.load_pem_x509_certificate(pkt.certChain[0], default_backend())
                    # ToDo certification integrity verify and common name verify
                    if (Upper_certification.issuer != self.root_CA_cert.issuer):
                        # Upper_certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        print("Upper_cert is not signed by a trusted root CA!")
                        return

                    self.cert_pubkB = server_certification.public_key()

                    try:
                        self.cert_pubkB.verify(pkt.signature, pkt.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                    except Exception as error:
                        logger.debug("client signature verify wrong: ECDH public key")
                        tls_handshake_packet = HandshakePacket(status=2)
                        self.transport.write(tls_handshake_packet.__serialize__())
                        self.transport.close()

                    try:
                        self.cert_pubkB.verify(pkt.nonceSignature, self.serialized_cnonce,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                    except Exception as error:
                        logger.debug("client signature verify wrong: nonce")
                        tls_handshake_packet = HandshakePacket(status=2)
                        self.transport.write(tls_handshake_packet.__serialize__())
                        self.transport.close()

                    self.serialized_snonce = str(pkt.nonce).encode('ASCII')
                    snonceSignature = self.client_sign_pvk.sign(self.serialized_snonce,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                    tls_handshake_packet = HandshakePacket(status=1, nonceSignature=snonceSignature)
                    self.transport.write(tls_handshake_packet.__serialize__())
                    # Generate shared key
                    recv_pubk = load_pem_public_key(pkt.pk, backend=default_backend())
                    self.shared_key = self.client_private_key.exchange(ec.ECDH(), recv_pubk)

                    print("Client TLS Handshake complete")

                    # Create hash 1, IVA, IVB
                    digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest1.update(self.shared_key)
                    hash1 = digest1.finalize()
                    self.ivA = hash1[0:12]
                    self.ivB = hash1[12:24]
                    print("client iva:", self.ivA)
                    print("client ivb:", self.ivB)

                    # Create hash2, encA
                    digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest2.update(hash1)
                    hash2 = digest2.finalize()
                    self.encA = hash2[0:16]
                    print("client enc:", self.encA)

                    # Create hash3, decA
                    digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest3.update(hash2)
                    hash3 = digest3.finalize()
                    self.decA = hash3[0:16]
                    print("client dec:", self.decA)

                    self.higherProtocol().connection_made(self.crap_transport)

            if pkt.DEFINITION_IDENTIFIER == "crap.datapacket":
                if self.mode == "server":
                    aesgcm = AESGCM(self.decB)
                    try:
                        decDataB = aesgcm.decrypt(self.ivA, pkt.data, None)

                    except Exception as error:
                        logger.debug("Server Decryption failed")

                    self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
                    self.higherProtocol().data_received(decDataB)

                if self.mode == "client":
                    aesgcm = AESGCM(self.decA)
                    try:
                        decDataA = aesgcm.decrypt(self.ivB, pkt.data, None)

                    except Exception as error:
                        logger.debug("Client Decryption failed")

                    self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")
                    self.higherProtocol().data_received(decDataA)


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),lambda: CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),lambda: CRAP(mode="server"))
