#!/usr/bin/python3

import datetime
import sys, os
import time
import threading
import traceback
import socketserver
import struct
from   Crypto.Cipher import AES
from   dnslib import *

CODING_TABLE  = "IQJ6WORKEGL5B4YS3NZMPDHVCUA7FX2T"
SECRET_KEY    = bytes((0xbe,0xa5,0x93,0x8e,0x43,0x4f,0x65,0xef,0x42,0xe7,0x11,0x45,0xc1,0xa0,0xfb,0x48,0xbf,0x8c,0x1a,0xf0,0x9b,0x36,0x88,0x4e,0x6d,0x6c,0x20,0x25,0xb4,0xf5,0xae,0x7c))
decodingTable = {}
for i,c in enumerate(CODING_TABLE.upper()):
  decodingTable[c] = i
CIPHER = AES.new( SECRET_KEY, AES.MODE_ECB )

# Port to listen on.  I use a high port to run as a non-root user and then
# map to it in iptables.  Alternatively change to port 53 and run as root.
PORT = 1853
SUBDOMAIN = '.dnsr.uk.to.'
LOGDIR = './'

class Crc16:
    def __init__( self ):
        self._resetRunnningCRC()
    def _resetRunnningCRC( self ):
        self.c=0xFFFF
    def _runningCRC( self, inputByte ):
        self.c ^= inputByte
        self.c &= 0xFFFF
        for b in range(8):             # For each bit in the byte
            if self.c & 1:
                self.c = (self.c >> 1) ^ 0xA001
            else: 
                self.c = (self.c >> 1)
            self.c &= 0xFFFF
    def getCrc( self, dataBytes ):
        self._resetRunnningCRC()
        for b in dataBytes:
            self._runningCRC( b )
        return self.c

class DnsDecoder:
    def __init__( self, SECRET_KEY, SUBDOMAIN, CODING_TABLE ):
        self.CODING_TABLE = CODING_TABLE
        self.SUBDOMAIN = SUBDOMAIN
        self.decodingTable = {}
        for i,c in enumerate(CODING_TABLE.upper()):
            self.decodingTable[c] = i
        self.cipher = AES.new( SECRET_KEY, AES.MODE_ECB )
        self.crc = Crc16()
    
    def _decodeBlock( self, messageBlock ):
        """ returns a bytes object """
        res = 0
        for i,c in enumerate(messageBlock):
            res |= self.decodingTable[c]<<(i*5)
        return res.to_bytes( 16, 'little' )
    
    def dnsDecode( self, qnString ):
        """ decode URL string and return payload as bytes """
        if not qnString.endswith( self.SUBDOMAIN ):
            raise RuntimeError("Bad hostname" + qnString.split(".")[-1])
        messageBlocks = qnString.replace( self.SUBDOMAIN, "" )
        resultBytes = bytearray()
        for messageBlock in messageBlocks.split("."):
            messageBlock.upper()
            resultBytes += self.cipher.decrypt( self._decodeBlock(messageBlock) )
        plCrc = resultBytes[-2]<<8 | resultBytes[-1]
        plLength = resultBytes[-3]
        resultBytes = resultBytes[:plLength]
        if self.crc.getCrc( resultBytes ) != plCrc:
            raise RuntimeError("CRC error")
        return resultBytes

dnsD = DnsDecoder( SECRET_KEY, SUBDOMAIN, CODING_TABLE )

def hexdump( res ):
  for i,b in enumerate(res):
    if( len(res)>16 and (i%16)==0 ):
      print( "\n  {:04x}: ".format(i), end="" )
    print( "{:02x} ".format(b), end="" )

def dns_response(data, clientAddress):
  """
  This is called for each received packet. Do something with it 
  """
  request = DNSRecord.parse(data)
  reply   = DNSRecord( DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q )
  qname   = request.q.qname
  qn      = str(qname)     #The actual Domain string with `.` at the end
  qtype   = request.q.qtype 
  qt      = QTYPE[qtype]   #Should be `A` if valid request

  print( '{0:s} : {1:3s} : {2:s}'.format(datetime.datetime.now(), qt, qn) )

  if qt == 'A' and qn.lower().endswith(SUBDOMAIN):
    try:
      payload = dnsD.dnsDecode( qn )
    except Exception as e:
      print( e )
      payload = bytearray()
    rIP = '13.37.13.{0}'.format(len(payload))
    reply.add_answer( RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=300, rdata=A(rIP)) )
    try:
      print(">>>", payload.decode(), "<<<" )
    except:
      hexdump( payload )
  return reply.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            data = self.get_data()
            self.send_data( dns_response( data, clientAddress=self.client_address ) )
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':
    print("Starting nameserver...")

    servers = [
        socketserver.ThreadingUDPServer(('', PORT), UDPRequestHandler),
        socketserver.ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print( "{0} server loop running in thread: {1}".format(s.RequestHandlerClass.__name__[:3],thread.name) )

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
