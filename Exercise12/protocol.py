from ..poop.protocol import POOP
from uuid import UUID
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import datetime
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER,LIST
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
        ("certChain",LIST(BUFFER,{Optional:True}))
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
        ("message", STRING),
    ]

class CRAPTransport(StackingTransport):
    def connect_protocol(self,protocol):
        self.protocol = protocol
    def write(self,data):
        self.protocol.send_datapacket(data)
    def close(self):
        self.protocol.transport.close()


class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.datasentA = None
        self.datasentB = None
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        self.status_crap = None
        self.privatekeyB = None
    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self.mode))
        self.transport = transport
        print(333333333333333333333333333333333)
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)
        print("Crap:connection_made")
        print(self.mode)
        if self.mode == "client":
            # Using
            print(1111111111111111111111111)
            self.privatekeyA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkA = self.privatekeyA.public_key()
            #save original pubkA
            publickA = pubkA 
            print(222222222222222222222222)
            # Create pk in packet (serialization)
            pubkA = pubkA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.datasentA = pubkA

            # Create long term key for signing
            self.signaturekA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.pubk_sign_A = self.signaturekA.public_key()
            print(555555)
            # Create signature
            sign_A = self.signaturekA.sign(self.datasentA,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

            # Create nonceA
            nonceA = randrange(2**32)
            self.nonceA = str(nonceA).encode('ASCII')
            print(66666)
            #load our certificate
            our_cert_temp = open('team5_signed.cert','rb').read()# to do our cert
            print(77777)
            our_private_key_temp = open('private_key.pem','rb').read()
            
            
            self.our_cert_final = x509.load_pem_x509_certificate(our_cert_temp,default_backend())
            print(231323131)
            self.our_private_key_final = load_pem_private_key(our_private_key_temp,password=None,backend=default_backend())
            print("ssssssssssssssssssssswqeqweqwe")
            
            print(213112331233)
            # Create certificate with the help of ephemeral private key
            subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MarryLand"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 5"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"20194.5.5.5"),
            ])
            certificate = x509.CertificateBuilder().subject_name(
            subject
            ).issuer_name(
            self.our_cert_final.subject #change the issuer of the cert
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
            x509.SubjectAlternativeName([x509.DNSName(u"20194.5.5.5")]),
            critical=False,
            # Sign our certificate with our private key
            ).sign(self.our_private_key_final, hashes.SHA256(), default_backend())

            print("certificate generate")
      # Create CertA to transmit (serialization)
            certA = certificate.public_bytes(Encoding.PEM)
            #print(self.pubk_sign_A.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
       #Create the cert chain
            self.chainA = [our_cert_temp]
            print(self.chainA)
            print("certificate")
            new_secure_packet = HandshakePacket(status=0, pk=self.datasentA, signature=sign_A, nonce=nonceA, cert=certA,certChain = self.chainA)
            self.transport.write(new_secure_packet.__serialize__())
            print("first craphanshake has ended")

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
            elif pkt_type == "crap.errorpacket":
                self.crap_error_recv(pkt)
            elif pkt_type == "crap.datapacket":
                self.crap_data_recv(pkt)
                print("{} Crap error: the recv pkt name: \"{}\" this is unexpected".format(
                    self.mode, pkt_type))
                return
    def crap_error_recv(self,packet):
        self.transport.close()


    def crap_handshake_recv(self, packet):
        if(self.status_crap == "ESTABLISTHED"):
            logger.debug("the connection has been established")
            return
        if self.mode == "server" and packet.status == 0:
            our_cert_temp = open('team5_signed.cert', 'rb').read()  # to do our cert
            our_private_key_temp = open('private_key.pem', 'rb').read()
            self.our_cert_final = x509.load_pem_x509_certificate(our_cert_temp, default_backend())
            self.our_private_key_final = load_pem_private_key(our_private_key_temp,password=None,backend=default_backend())
            certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
            self.get_pubKA = certification.public_key()
            # print(self.get_pubKA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

            try:
                logger.debug("the server sends back handshake")
                self.get_pubKA.verify(packet.signature, packet.pk,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                our_addr = self.our_cert_final.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                receive_addr = certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                print("Team address:", our_addr)
                print("Client address:", receive_addr)
                if our_addr in receive_addr:
                    print("Verify success")
                    pass
                else:
                    raise

            except Exception as error:
                logger.debug("wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()
            # Create Server long term key
            print("good")
            
            self.privatekeyB = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkB = self.privatekeyB.public_key()
            print("good2")
            # serialization
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
            tmp_nonceB = randrange(2**32)
            self.nonceB = str(tmp_nonceB).encode('ASCII')

            # Reveive nonceA
            nonceA = str(packet.nonce).encode('ASCII')

            # Generate shared key
            pubkB_recv = load_pem_public_key(packet.pk, backend=default_backend())
            self.server_shared_key = self.privatekeyB.exchange(ec.ECDH(), pubkB_recv)

            print("generating ")
            # Create certificate with the help of ephemeral private key
            subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MarryLand"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Peskvile"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 5"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"20194.5.5.5"),
            ])
            certificate = x509.CertificateBuilder().subject_name(
            subject
            ).issuer_name(
            self.our_cert_final.subject
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
            ).sign(self.our_private_key_final, hashes.SHA256(), default_backend())

            # Create CertB to transmit (serialization)





            certB = certificate.public_bytes(Encoding.PEM)


            #create certChain
            self.chainB = [our_cert_temp]
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
            #Generating the hash
            digest1_temp = hashes.Hash(hashes.SHA256(),backend = default_backend())
            digest1_temp.update(self.server_shared_key)
            hash1 = digest1_temp.finalize()
            self.IVA = hash1[0:12]
            self.IVB = hash1[12:24]
            print("server's IVA =",self.IVA)
            print("server's IVB =",self.IVB)
            digest2_temp = hashes.Hash(hashes.SHA256(),backend = default_backend())
            digest2_temp.update(hash1)
            hash2 = digest2_temp.finalize()
            self.decB = hash2[0:16]
            print("server's dec:",self.decB)
            digest3_temp = hashes.Hash(hashes.SHA256(),backend = default_backend())
            digest3_temp.update(hash2)
            hash3 = digest3_temp.finalize()
            self.encB = hash3[0:16]
            print("server's dec:", self.encB)
            self.status_crap = "ESTABLISHED"
            self.higherProtocol().connection_made(self.higher_transport)



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
                our_addr = self.our_cert_final.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                receive_addr = certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                print("Team address:", our_addr)
                print("Client address:", receive_addr)
                if our_addr in receive_addr:
                    print("Verify success")
                    pass
                else:
                    raise
            except Exception as error:
                logger.debug("client verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            # Generate shared key
            pubkA_recv = load_pem_public_key(packet.pk, backend=default_backend())
            print(pubkA_recv)
            print(self.privatekeyB)
            client_shared_key = self.privatekeyB.exchange(ec.ECDH(), pubkA_recv)
            
            # Reveive nonceB
            nonceB = str(packet.nonce).encode('ASCII')

            nonceSignatureA = self.signaturekA.sign(nonceB,
                                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH),
                                               hashes.SHA256())

            new_secure_packet = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
            self.transport.write(new_secure_packet.__serialize__())
            print("The third handshake has been established")
            # Generating the hash
            digest1_temp = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest1_temp.update(self.server_shared_key)
            hash1 = digest1_temp.finalize()
            self.IVA = hash1[0:12]
            self.IVB = hash1[12:24]
            print("server's IVA =", self.IVA)
            print("server's IVB =", self.IVB)
            digest2_temp = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest2_temp.update(hash1)
            hash2 = digest2_temp.finalize()
            self.decB = hash2[0:16]
            print("server's dec:", self.decB)
            digest3_temp = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest3_temp.update(hash2)
            hash3 = digest3_temp.finalize()
            self.encB = hash3[0:16]
            print("server's dec:", self.encB)
            self.status_crap = "ESTABLISHED"
            self.higherProtocol().connection_made(self.higher_transport)
    def send_datapacket(self,data):
        if self.mode == "client":
            aes = AESGCM(self.encA)
            encryptdataClient = aes.encrypt(self.IVA,data,None)
            self.IVA = (int.from_bytes(self.IVA, "big") + 1).to_bytes(12, "big")
            new_encrpyt_packet = DataPacket(data = encryptdataClient)
            self.transport.write(new_encrpyt_packet.__serialize__())
            print("Client has sent encrypted data")
            aes = AESGCM(self.encA)
            encryptdataServer = aes.encrypt(self.IVB,data,None)
            self.IVB = (int.from_bytes(self.IVB, "big") + 1).to_bytes(12, "big")
            new_encrpyt_packet = DataPacket(data = encryptdataServer)
            self.transport.write(new_encrpyt_packet.__serialize__())
            print("Server has sent encrypted data")
    def crap_data_recv(self,packet):
        if self.mode == "server":
            aes = AESGCM(self.decB)
            try:
                decnewB = aes.decrypt(self.IVA, packet.data, None)

            except Exception as error:
                logger.debug("Server Decryption failed")

            self.IVA = (int.from_bytes(self.IVA, "big") + 1).to_bytes(12, "big")
            self.higherProtocol().data_received(decnewB)

        if self.mode == "client":
            aesgcm = AESGCM(self.decA)
            try:
                decnewA = aesgcm.decrypt(self.ivB, packet.data, None)

            except Exception as error:
                logger.debug("Client Decryption failed")

            self.IVB = (int.from_bytes(self.IVB, "big") + 1).to_bytes(12, "big")
            self.higherProtocol().data_received(decnewA)
SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: CRAP(mode="server"))
