from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import os
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
        self.protocol.send_datapacket(data)
        

    def close(self):
        self.protocol.transport.close()


class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("____________{} crap __init__()_________".format(mode))
        super().__init__()
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
    def send_datapacket(self, data):
        if self.mode == "client":
            aesg = AESGCM(self.encrptA)
            encDataA = aesg.encrypt(self.IVA, data, None)
            self.IVA = (int.from_bytes(self.IVA, "big") + 1).to_bytes(12, "big")
            new_packet = DataPacket(data=encDataA)
            self.transport.write(new_packet.__serialize__())
            print("Client send encrypted data")

        if self.mode == "server":
            aesg = AESGCM(self.encB)
            encDataB = aesg.encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")
            new_packet = DataPacket(data=encDataB)
            self.transport.write(new_packet.__serialize__())
            print("server send encrypted data")
          
    def connection_made(self, transport):
        logger.debug("{} CRAP: connection made".format(self.mode))
        self.transport = transport
        self.crap_transport = CrapTransport(self.transport)
        self.crap_transport.set_protocol(self)

        if self.mode == "client":
            client_privak= ec.generate_private_key(ec.SECP384R1(), default_backend())
            client_pubk = client_privak.public_key()
            client_sign_pvk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            client_sign_pbk = client_sign_pvk.public_key()
            root_cert = open('20194_root.cert', 'rb').read()
            team5_CA_cert = open('team5_signed.cert', 'rb').read()
            team5_CA_private_key = open('private_key.pem', 'rb').read()
            self.team5_sign_pvk = load_pem_private_key(team5_CA_private_key, password=None, backend=default_backend())
            self.root_cert = x509.load_pem_x509_certificate(root_cert, default_backend())
            self.team5_CA_cert = x509.load_pem_x509_certificate(team5_CA_cert, default_backend())
            self.team5_CA_sign_pbk = self.team5_sign_pvk.public_key()
            self.root_sign_pbk = self.root_cert.public_key()


            NonceA = randrange(2 ** 32)
            self.serialized_NonceA = str(NonceA).encode('ASCII')

            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.5.20.30'), ]))
            builder = builder.issuer_name(self.team5_CA_cert.subject)
            builder = builder.not_valid_before(datetime.datetime.today() - (datetime.timedelta(days=10)))
            builder = builder.not_valid_after(datetime.datetime.today() + (datetime.timedelta(days=10)))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(client_sign_pbk)
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.5.20.30")]), critical=False)
            certificate = builder.sign(private_key=self.team5_sign_pvk, algorithm=hashes.SHA256(),
                                       backend=default_backend())
            client_cert = certificate.public_bytes(Encoding.PEM)

            data = client_pubk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            sigA = client_sign_pvk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

            secure_new_packet = HandshakePacket(status=0,pk = data,signature = sigA,nonce = NonceA,cert = client_cert,certChain=[team5_CA_cert])
            self.transport.write(secure_new_packet.__serialize__())
            logger.debug("Client send secure handshake!")





    def data_received(self, buffer):
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
        #define function of processing craphandshake
            def process_craphandshake_packet(pkt):
                logger.debug("***{} CRAP: Received a secure handshakepacket".format(self.mode))
                if self.mode == "server":
                    root_cert = open('20194_root.cert', 'rb').read()
                    team5_CA_cert = open('team5_signed.cert', 'rb').read()
                    team5_CA_private_key = open('private_key.pem', 'rb').read()

                    self.team5_sign_pvk = load_pem_private_key(team5_CA_private_key, password=None,
                                                                  backend=default_backend())
                    self.root_cert = x509.load_pem_x509_certificate(root_cert, default_backend())
                    self.team5_CA_cert = x509.load_pem_x509_certificate(team5_CA_cert, default_backend())
                    self.team5_CA_sign_pbk = self.team5_sign_pvk.public_key()
                    self.root_sign_pbk = self.root_cert.public_key()

                    if pkt.status == 0:
                        
                        try:
                            client_certification = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                            received_certification = x509.load_pem_x509_certificate(pkt.certChain[0], default_backend())

                            if(received_certification.issuer != self.root_cert.issuer):
                                print("Upper_cert is not signed by a trusted root CA!")
                                return

                            self.cert_pubkA = client_certification.public_key()
                            self.cert_pubkA.verify(pkt.signature, pkt.pk,
                                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                        except Exception as error:
                            print("Wrong signature")
                            secure_new_packet = HandshakePacket(status=2)
                            self.transport.write(secure_new_packet.__serialize__())
                            self.transport.close()



                        print("Server cert successful")
                        server_privak = ec.generate_private_key(ec.SECP384R1(), default_backend())
                        server_pubk = server_privak.public_key()
                        server_sign_pvk = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                                        backend=default_backend())
                        server_sign_pbk = server_sign_pvk.public_key()
                        #generate nonce number
                        NonceB = randrange(2**32)
                        self.serialized_NonceB = str(NonceB).encode('ASCII')
                        self.serialized_NonceA = str(pkt.nonce).encode('ASCII')

                        #generate shared_key
                        recv_pbk = load_pem_public_key(pkt.pk, backend=default_backend())
                        self.shared_key = server_privak.exchange(ec.ECDH(), recv_pbk)

                        print("111111111111111111")
                        data = server_pubk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        sigB = server_sign_pvk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                        secure_new_packet = HandshakePacket(status=1,pk = data, signature = sigB,nonce = NonceB)
                        print("2222222222222222")

                        builder = x509.CertificateBuilder()
                        builder = builder.subject_name(
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'20194.5.20.30'), ]))
                        builder = builder.issuer_name(self.team5_CA_cert.subject)
                        builder = builder.not_valid_before(datetime.datetime.today() - (datetime.timedelta(days=10)))
                        builder = builder.not_valid_after(datetime.datetime.today() + (datetime.timedelta(days=10)))
                        builder = builder.serial_number(x509.random_serial_number())
                        builder = builder.public_key(server_sign_pbk)
                        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.5.20.30")]),
                                                        critical=False)
                        certificate = builder.sign(private_key=self.team5_sign_pvk, algorithm=hashes.SHA256(),
                                                   backend=default_backend())
                        server_cert = certificate.public_bytes(Encoding.PEM)
                        print("Server get signed cert success!!!")

                        secure_new_packet.cert = server_cert
                        secure_new_packet.certChain = [team5_CA_cert]

                        cnonceSignature = server_sign_pvk.sign(self.serialized_NonceA, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                        secure_new_packet.nonceSignature = cnonceSignature

                        self.transport.write(secure_new_packet.__serialize__())
                        logger.debug("Server send secure handshake!")

                    elif pkt.status == 1:
                        try:
                            self.cert_pubkA.verify(pkt.nonceSignature, self.serialized_NonceB,
                                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                  salt_length=padding.PSS.MAX_LENGTH),
                                                      hashes.SHA256())

                        except Exception as error:
                            logger.debug("server signature verify wrong: nonce")
                            secure_new_packet = HandshakePacket(status=2)
                            self.transport.write(secure_new_packet.__serialize__())
                            self.transport.close()
                        print("Server secure Handshake complete")

                        # Create hash 1, IVA, ivB
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



                elif self.mode == "client":
                    if pkt.status == 1:
                        try:
                            server_certification = x509.load_pem_x509_certificate(pkt.cert, default_backend())
                            received_certification = x509.load_pem_x509_certificate(pkt.certChain[0], default_backend())
                        # ToDo certification integrity verify and common name verify
                            if (received_certification.issuer != self.root_cert.issuer):
                            # received_certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                                print("Upper_cert is not signed by a trusted root CA!")
                                return

                            self.cert_pubkB = server_certification.public_key()
                            self.cert_pubkB.verify(pkt.signature, pkt.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                        except Exception as error:
                            logger.debug("Client wrong signature")
                            secure_new_packet = HandshakePacket(status=2)
                            self.transport.write(secure_new_packet.__serialize__())
                            self.transport.close()

                        try:
                            self.cert_pubkB.verify(pkt.nonceSignature, self.serialized_NonceA,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                        except Exception as error:
                            logger.debug("nonce problem")
                            secure_new_packet = HandshakePacket(status=2)
                            self.transport.write(secure_new_packet.__serialize__())
                            self.transport.close()

                        self.serialized_NonceB = str(pkt.nonce).encode('ASCII')
                        snonceSignature = client_sign_pvk.sign(self.serialized_NonceB,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                        secure_new_packet = HandshakePacket(status=1, nonceSignature=snonceSignature)
                        self.transport.write(secure_new_packet.__serialize__())
                        # Generate shared key
                        recv_pubk = load_pem_public_key(pkt.pk, backend=default_backend())
                        self.shared_key = client_privak.exchange(ec.ECDH(), recv_pubk)

                        print("Client secure Handshake complete")

                        # Create hash 1, IVA, ivB
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
                        self.encrptA = hash2[0:16]
                        print("client enc:", self.encrptA)

                        # Create hash3, decA
                        digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                        digest3.update(hash2)
                        hash3 = digest3.finalize()
                        self.decryptA = hash3[0:16]
                        print("client dec:", self.decryptA)

                        self.higherProtocol().connection_made(self.crap_transport)
                        print("final key (IVA...) has been generated")
            def process_data_packet(pkt):
                if self.mode == "server":
                    aesg = AESGCM(self.decB)
                    decData = aesg.decrypt(self.ivA, pkt.data, None)
                    print("decrypt succeed for server")
                    self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
                    self.higherProtocol().data_received(decData)

                if self.mode == "client":
                    aesg = AESGCM(self.decryptA)
                    decData = aesg.decrypt(self.ivB, pkt.data, None)
                    self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")
                    self.higherProtocol().data_received(decData)
                    print("decrypt succeed for client")
            if pkt.DEFINITION_IDENTIFIER == "crap.handshakepacket":
                process_craphandshake_packet(pkt)
            if pkt.DEFINITION_IDENTIFIER == "crap.datapacket":
                process_data_packet(pkt)
        





SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),lambda: CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),lambda: CRAP(mode="server"))
