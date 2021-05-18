

import socket

def genrtppacket( version=2, extenson=0, csrccount=0, marker=0, payloadtype=8, sequencenumber=0, timestamp=0, ssrc=0, csrclist=0 ):

  rtppacket = bytearray( 172 )
  rtppacket[ 0 ] = rtppacket[ 0 ] | ( version << 6 )
  rtppacket[ 0 ] = rtppacket[ 0 ] | ( ( extenson << 4 ) & 0x10 )
  rtppacket[ 0 ] = rtppacket[ 0 ] | ( csrccount & 0x0f )
  rtppacket[ 1 ] = rtppacket[ 1 ] | ( ( marker << 7 ) & 0x80 )
  rtppacket[ 1 ] = rtppacket[ 1 ] | ( payloadtype & 0x7f )

  sequencenumber = socket.htons( sequencenumber )
  rtppacket[ 2 ] = sequencenumber & 0xff
  rtppacket[ 3 ] = sequencenumber >> 8

  timestamp = socket.htonl( timestamp )
  rtppacket[ 4 ] = timestamp & 0xff
  rtppacket[ 5 ] = ( timestamp >> 8 ) & 0xff
  rtppacket[ 6 ] = ( timestamp  >> 16 ) & 0xff
  rtppacket[ 7 ] = timestamp >> 24

  ssrc = socket.htonl( ssrc )
  rtppacket[ 8 ] = ssrc & 0xff
  rtppacket[ 9 ] = ( ssrc >> 8 ) & 0xff
  rtppacket[ 10 ] = ( ssrc  >> 16 ) & 0xff
  rtppacket[ 11 ] = ssrc >> 24

  rtppacket[ 12 ] = socket.htonl( csrclist )

  return rtppacket
