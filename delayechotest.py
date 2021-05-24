#!/usr/bin/env python3

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
import random

echotarget = "8"
localrtpport = int ( random.randrange( 20000, 30000 ) / 2 ) * 2
stallatsequencenumber = []
stalltimesec = 1


################################################################################
'''
Our functions for sending and receiving RTP Data
'''
################################################################################
def roundtriptimesender( shared, sock, remotehost, remoteport, ssrc ):

  starttime = time.perf_counter()
  nexttime = starttime + 0.02

  sequencenumber = 0
  timestamp = 0

  indexlastsent = 0

  while True == shared[ "running" ]:

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
    time.sleep( 0.015 )
    while time.perf_counter() < nexttime:
      pass

    nexttime = nexttime + 0.02

  print( "Sent " + str( sequencenumber ) + " packets" )

def roundtriptimerecevier( shared, sock ):

  running = True
  receivedcount = 0

  starttime = time.time()

  while running:
    pk, address = sock.recvfrom( 1500 )
    receivedcount = receivedcount + 1

    with shared[ "threadlock" ]:
      running = shared[ "running" ]

      if pk[ 15 ] == shared[ "indexlookingfor" ]:
        # End the timer
        nowtime = time.time()
        elapsedmin = int( ( nowtime - starttime ) / 60 )
        elapsedsec = int( ( nowtime - starttime ) % 60 )

        print( "elapsed: {elapsedmin}:{elapsedsec} time taken: {timetaken}".format( elapsedmin=elapsedmin, elapsedsec=elapsedsec, timetaken=str( time.perf_counter() - shared[ "timer" ] ) ) )
        shared[ "indexlookingfor" ] = ( shared[ "indexlookingfor" ] + 1 ) % 10

  print( "Received " + str( receivedcount ) + " packets" )

def roundtriptime( localport, remotehost, remoteport, ssrc ):

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

  shared[ "sender" ] = threading.Thread( target=roundtriptimesender, args=( shared, sock, remotehost, remoteport, ssrc ) )
  shared[ "receiver" ] = threading.Thread( target=roundtriptimerecevier, args=( shared, sock, ) )

  shared[ "sender" ].start()
  shared[ "receiver" ].start()

  return shared

def finishroundtriptime( shared ):

  shared[ "running" ] = False

  shared[ "receiver" ].join()
  shared[ "receiver" ].join()


################################################################################
'''
Our test script
'''
################################################################################

c = sip.client()
s = sip.newcall( c, echotarget )

sip.trace( s )
sip.sendinvite( s )
assert 407 == sip.wait( s )
sip.sendack( s )

sip.sendinvite( s, rtpport=localrtpport, auth=True )
assert 100 == sip.wait( s )
assert 200 == sip.wait( s )
sip.sendack( s )

remotehost, remotertpport, session = sip.getremoteaudiohostport( s )

print( "Remote session: " + remotehost + ":" + str( remotertpport ) + ", " + str( session ) )
roundtriptime( localrtpport, remotehost, remotertpport, session )

# Handle session timers
for i in range( 100 ):
  if "INVITE" == sip.wait( s ):
    print( "INVITE" )
    sip.send200( s )
    assert "ACK" == sip.wait( s )

# Now hangup the call
sip.sendbye( s )
assert 200 == sip.wait( s )

sip.closetrace( s )

print( "Test completed" )
