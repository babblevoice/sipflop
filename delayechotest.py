#!/usr/bin/env python

################################################################################
'''
Test script measure the round trip time for RTP data (i.e. reflective of
speech delay). Times are printed to the screen for the delay measured.
'''
################################################################################

import time
import threading
import socket
from sflib import sip
from sflib import rtp

echotarget = "8"
localrtpport = 10000
stallatsequencenumber = [ 10, 200, 800, 1600 ]
stalltimesec = 5


################################################################################
'''
Our functions for sending and receiving RTP Data
'''
################################################################################
def roundtriptimesender( shared, sock, remotehost, remoteport, duration, ssrc ):

  starttime = time.perf_counter()
  endtime = starttime + duration
  nexttime = starttime + 0.02

  sequencenumber = 0
  timestamp = 0

  indexlastsent = 0

  while nexttime < endtime:

    # Stall
    if shared[ "stalltimesec" ] > 0 and sequencenumber in stallatsequencenumber:
      time.sleep( shared[ "stalltimesec" ] )

      # Simulate sending data before the RTP sesion on FS starts - which will build up buffers
      # in the underlying socket on FS.
      for x in range( 50 * shared[ "stalltimesec" ] ):
        pk = rtp.genrtppacket( sequencenumber=sequencenumber, timestamp=timestamp, ssrc=ssrc )
        sequencenumber = sequencenumber + 1
        timestamp = timestamp + 160
        sock.sendto( pk, ( remotehost, remoteport ) )

    pk = rtp.genrtppacket( sequencenumber=sequencenumber, timestamp=timestamp, ssrc=ssrc )
    sequencenumber = sequencenumber + 1
    timestamp = timestamp + 160

    with  shared[ "threadlock" ]:
      pk[ 15 ] = shared[ "indexlookingfor" ]

      # start the timer
      if indexlastsent != pk[ 15 ]:
        shared[ "timer" ] = time.perf_counter()

    indexlastsent = pk[ 15 ]
    sock.sendto( pk, ( remotehost, remoteport ) )

    # Sleep half the time then sit on a hi res clock
    time.sleep( 0.01 )
    while time.perf_counter() < nexttime:
      pass

    nexttime = nexttime + 0.02

  with  shared[ "threadlock" ]:
    shared[ "running" ] = False

  print( "Sent " + str( sequencenumber ) + " packets" )

def roundtriptimerecevier( shared, sock ):

  running = True
  receivedcount = 0
  while running:
    pk, address = sock.recvfrom( 1500 )
    receivedcount = receivedcount + 1

    with shared[ "threadlock" ]:
      running = shared[ "running" ]

      if pk[ 15 ] == shared[ "indexlookingfor" ]:
        # End the timer
        print( "time taken:" + str( time.perf_counter() - shared[ "timer" ] ) )
        shared[ "indexlookingfor" ] = ( shared[ "indexlookingfor" ] + 1 ) % 10

  print( "Received " + str( receivedcount ) + " packets" )

def roundtriptime( localport, remotehost, remoteport, ssrc, duration=60 ):

  shared = {
    "indexlookingfor": 1,
    "timer": 0.0,
    "threadlock": threading.Lock(),
    "running": True,
    "stalltimesec": stalltimesec
  }

  sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP )
  sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
  sock.setsockopt( socket.IPPROTO_IP, socket.IP_TOS, 184 ) # EF ( DSCP=46, ECN=0 )
  sock.bind( ( "", localport ) )

  sender = threading.Thread( target=roundtriptimesender, args=( shared, sock, remotehost, remoteport, duration, ssrc ) )
  receiver = threading.Thread( target=roundtriptimerecevier, args=( shared, sock, ) )

  sender.start()
  receiver.start()

  sender.join()
  receiver.join()


################################################################################
'''
Our test script
'''
################################################################################

c = sip.client()
s = sip.newcall( c, echotarget )

sip.trace( s )
sip.sendinvite( s )
sip.waitfor( s, 407 )
sip.sendack( s )

sip.sendinvite( s, rtpport=localrtpport, auth=True )
sip.waitfor( s, 100 )
sip.waitfor( s, 200 )
sip.sendack( s )

remotehost, remotertpport, session = sip.getremoteaudiohostport( s )

print( "Remote session: " + remotehost + ":" + str( remotertpport ) + ", " + str( session ) )
roundtriptime( localrtpport, remotehost, remotertpport, session, duration=60 )

sip.sendbye( s )
sip.waitfor( s, 200 )

sip.closetrace( s )

print( "Test completed" )
