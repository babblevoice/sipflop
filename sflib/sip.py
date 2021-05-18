

import json
import uuid

import socket
import random

import re

# MD5 for auth
import hashlib

# For tracing
import tempfile
from datetime import datetime

conf = json.load( open( "config.json" ) )


# regexes for pulling out info
retotag = re.compile( r"^To: <(.*)>;?tag=([a-zA-Z0-9\-]*)?.*$", re.MULTILINE | re.IGNORECASE )
refromtag = re.compile( r"^From: <(.*)>;?tag=([a-zA-Z0-9\-]*)?.*$", re.MULTILINE | re.IGNORECASE )
cseqsearch = re.compile( r"^CSeq: ([a-zA-Z0-9\-]*)? (INVITE|ACK|BYE|CANCEL|OPTIONS|MESSAGE|REFER|UPDATE|NOTIFY)", re.MULTILINE | re.IGNORECASE )
proxyauthrealmauth = re.compile( r'^Proxy-Authenticate: Digest(.*)?realm="([a-zA-Z0-9\.]*)?",(.*)?', re.MULTILINE | re.IGNORECASE )
proxyauthnonce = re.compile( r'^Proxy-Authenticate: Digest(.*)?nonce="([a-zA-Z0-9\.\-]*)?",(.*)?', re.MULTILINE | re.IGNORECASE )
qopcheck = re.compile( r'^Proxy-Authenticate: Digest(.*)?qop="(auth)",?(.*)?', re.MULTILINE | re.IGNORECASE )
codesearch = re.compile( r'^SIP/2.0 (\d\d\d) .*$', re.MULTILINE | re.IGNORECASE )
contentlengthsearch = re.compile( r'^Content-Length: (\d{0,10})?', re.MULTILINE | re.IGNORECASE )
sdpaudioportsearch = re.compile( r'^m=audio (\d{1,5})?.*?$', re.MULTILINE | re.IGNORECASE )
sdpaudioipsearch = re.compile( r'^c=IN IP4 (.*)?$', re.MULTILINE | re.IGNORECASE )
sdpsessionsearch = re.compile( r'^o=(\w*)? (\w*)? (.*)?$', re.MULTILINE | re.IGNORECASE )
sipactionsearch = re.compile( r'^(INVITE|ACK|BYE|CANCEL|OPTIONS|MESSAGE|REFER|UPDATE|NOTIFY) (.*)? SIP\/2.0', re.MULTILINE | re.IGNORECASE )
contactsearch = re.compile( r'^Contact: <(.*)?>', re.MULTILINE | re.IGNORECASE )
viaheader = re.compile( r'^Via: (.*)?\r\n', re.MULTILINE | re.IGNORECASE )

def getlocalip():
  s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
  s.connect( ( "8.8.8.8", 53 ) )
  localip = s.getsockname()[ 0 ]
  s.close()
  return localip
localip = getlocalip()

def client():
  sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP )
  sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
  sock.bind( ( "", random.randrange( 1024, 9999 ) ) )

  return sock

def trace( s ):
  s[ "tracefile" ] = tempfile.NamedTemporaryFile( mode = 'w+', delete=False )
  print( "SIP tracing to file " + s[ "tracefile" ].name )

def closetrace( s ):
  if "tracefile" in s:
    s[ "tracefile" ].close()

# s = session
# h = headers (SIP headers)
# b = body (SDP)
def sendto( s, h, b=None ):
  msg = h + "\r\n"
  if None != b and len( b ) > 0:
    msg += b

  msg = msg.replace( "\r\n", "\n" ).replace( "\n", "\r\n" )

  s[ "sock" ].sendto( bytearray( msg, "utf-8" ), ( s[ "host" ], s[ "port" ] ) )

  if "tracefile" in s:
    s[ "tracefile" ].write( "==================================================\r\n{time} Sending {bytes} bytes:\r\n==================================================\r\n".format( time=str( datetime.now() ), bytes=len( msg ) ) )
    s[ "tracefile" ].write( msg )

def recv( s ):
  data, addr = s[ "sock" ].recvfrom( 1500 )
  msg = data.decode()

  if "tracefile" in s:
    s[ "tracefile" ].write( "==================================================\r\n{time} Received {bytes} bytes:\r\n==================================================\r\n".format( time=str( datetime.now() ), bytes=len( msg ) ) )
    s[ "tracefile" ].write( msg )

  return msg

def newcall( c, target ):
  return {
    "sock": c,
    "cseq": 1,
    "target": target,
    "localport": c.getsockname()[ 1 ],
    "host": conf[ "sip" ][ "host" ],
    "realm": conf[ "sip" ][ "realm" ],
    "user": conf[ "sip" ][ "user" ],
    "secret": conf[ "sip" ][ "secret" ],
    "port": conf[ "sip" ][ "port" ],
    "callid": str( uuid.uuid4() ),
    "history": [],
    "tags": {
      "ours": str( uuid.uuid4() )[ :8 ],
      "theirs": ""
    },
    "auth": {

    }
  }

def calcauthresponse( username, password, realm, method, uri, nonce, cnonce, nc, qop ):

  # ha1
  ha1hash = hashlib.md5( ":".join( [ username, realm, password ] ).encode( "utf-8" ) ).hexdigest()
  # ha2
  ha2hash = hashlib.md5( ":".join( [ method, uri ] ).encode( "utf-8" ) ).hexdigest()

  # Response
  response = [ ha1hash, nonce ]

  if None != cnonce and len( cnonce ) > 0:
    response.append( nc )
    response.append( cnonce )

  if None != qop and len( qop ) > 0:
    response.append( qop )

  response.append( ha2hash )
  return hashlib.md5( ":".join( response ).encode( "utf-8" ) ).hexdigest()

def addauthheader( h, method, uri, s ):

  s[ "auth" ][ "cnonce" ] = str( uuid.uuid4() )
  nc = "{:08d}".format( s[ "auth" ][ "nc" ] )
  s[ "auth" ][ "nc" ] = s[ "auth" ][ "nc" ] + 1

  resp = calcauthresponse( s[ "user" ],
                            s[ "secret" ],
                            s[ "auth" ][ "realm" ],
                            method,
                            uri,
                            s[ "auth" ][ "nonce" ],
                            s[ "auth" ][ "cnonce" ],
                            nc,
                            s[ "auth" ][ "qop" ] )

  h += 'Proxy-Authorization: Digest username="{user}",realm="{realm}",nonce="{nonce}",uri="{uri}",response="{response}",cnonce="{cnonce}",nc={nc},qop={qop},algorithm=MD5\r\n'.format(
              user=s[ "user" ],
              realm=s[ "auth" ][ "realm" ],
              nonce=s[ "auth" ][ "nonce" ],
              uri=uri,
              response=resp,
              cnonce=s[ "auth" ][ "cnonce" ],
              nc=nc,
              qop=s[ "auth" ][ "qop" ]
            )

  return h

def sendinvite( s, auth=False, rtpport=10000 ):

  s[ "sdpsessversion" ] = 1
  s[ "rtpport" ] = rtpport

  s[ "sdptemplate" ] = '''v=0
o=Z 1620481633724 {sessversion} IN IP4 {localip}
s=Z
c=IN IP4 {localip}
t=0 0
m=audio {rtpport} RTP/AVP 8 101
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
'''.replace( "\n", "\r\n" )

  s[ "sdp" ] = s[ "sdptemplate" ].format(
                            localip=localip,
                            rtpport=s[ "rtpport" ],
                            sessversion = s[ "sdpsessversion" ] )

  s[ "uri" ] = "sip:{target}@{realm};transport=UDP".format( target=s[ "target" ], realm=s[ "realm" ] )

  sipinvite = '''INVITE {uri} SIP/2.0
Via: SIP/2.0/UDP {localip}:{localport};rport
Max-Forwards: 70
Contact: <sip:{user}@{localip}:{localport};transport=UDP>
To: <sip:{target}@{realm}>
From: <{uri}>;tag={ourtag}
Call-ID: {callid}
CSeq: {cseq} INVITE
Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE
Content-Type: application/sdp
User-Agent: sipflop
Allow-Events: presence, kpml, talk
Content-Length: {sdplength}
'''.format( uri=s[ "uri" ],
            localip=localip,
            localport=s[ "localport" ],
            user=s[ "user" ],
            cseq=s[ "cseq" ],
            realm=s[ "realm" ],
            target=s[ "target" ],
            callid=s[ "callid" ],
            ourtag=s[ "tags" ][ "ours" ],
            sdplength=len( s[ "sdp" ] ) )

  if auth:
    sipinvite = addauthheader( sipinvite, "INVITE", s[ "uri" ], s )

  sendto( s, sipinvite, s[ "sdp" ] )

def sendack( s, auth=True ):

  sipack = '''ACK {uri} SIP/2.0
Via: SIP/2.0/UDP {localip}:{localport};rport
Max-Forwards: 70
To: <sip:{target}@{realm}>;tag={theirtag}
From: <{uri}>;tag={ourtag}
Call-ID: {callid}
CSeq: {cseq} ACK
Content-Length: 0
'''.format( uri=s[ "uri" ],
            localip=localip,
            localport=s[ "localport" ],
            user=s[ "user" ],
            callid=s[ "callid" ],
            ourtag=s[ "tags" ][ "ours" ],
            theirtag=s[ "tags" ][ "theirs" ],
            cseq=s[ "cseq" ],
            realm=s[ "realm" ],
            target=s[ "target" ] )

  if auth:
    sipack = addauthheader( sipack, "ACK", s[ "uri" ], s )

  sendto( s, sipack )
  s[ "cseq" ] = s[ "cseq" ] + 1

def sendbye( s, auth=True ):

  sipbye = '''BYE {uri} SIP/2.0
Via: SIP/2.0/UDP {localip}:{localport};rport
Max-Forwards: 70
Contact: <sip:{user}@{localip}:{localport};transport=UDP>
To: <sip:{target}@{realm}>;tag={theirtag}
From: <{uri}>;tag={ourtag}
Call-ID: {callid}
CSeq: {cseq} BYE
User-Agent: sipflop
Content-Length: 0
'''.format( uri=s[ "uri" ],
            localport=s[ "localport" ],
            localip=localip,
            user=s[ "user" ],
            target=s[ "target" ],
            realm=s[ "realm" ],
            ourtag=s[ "tags" ][ "ours" ],
            theirtag=s[ "tags" ][ "theirs" ],
            cseq=s[ "cseq" ],
            callid=s[ "callid" ] )

  if auth:
    sipbye = addauthheader( sipbye, "BYE", s[ "uri" ], s )

  sendto( s, sipbye )

def send200( s, method="INVITE" ):

  sip200 = '''SIP/2.0 200 OK
Via: {via}
Require: timer
Contact: <{contact}>
To: <{touri}>;tag={theirtag}
From: <{fromuri}>;tag={ourtag}
Call-ID: {callid}
CSeq: {cseq} {method}
Session-Expires: 120;refresher=uac
Min-SE: 120
Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE
Content-Type: application/sdp
User-Agent: sipflop
Allow-Events: presence, kpml, talk
Content-Length: {sdplength}
'''.format( uri=s[ "uri" ],
            localport=s[ "localport" ],
            localip=localip,
            contact=s[ "uri" ],
            target=s[ "target" ],
            realm=s[ "realm" ],
            ourtag=s[ "tags" ][ "ours" ],
            theirtag=s[ "tags" ][ "theirs" ],
            cseq=s[ "cseq" ],
            callid=s[ "callid" ],
            sdplength=len( s[ "sdp" ] ),
            method=method,
            fromuri=s[ "fromuri" ],
            touri=s[ "touri" ],
            via=s[ "via" ]
          )

  # sdp in s[ "sdp" ]
  s[ "sdpsessversion" ] = s[ "sdpsessversion" ] + 1
  s[ "sdp" ] = s[ "sdptemplate" ].format(
                      localip=localip,
                      rtpport=s[ "rtpport" ],
                      sessversion=s[ "sdpsessversion" ] )

  print( "Sending: " + sip200 )
  sendto( s, sip200, s[ "sdp" ] )

def wait( s ):

  p = recv( s )
  s[ "history" ].append( p )

  recevivedcode = codesearch.search( p )

  if None == recevivedcode:
    # re-invite?
    action = sipactionsearch.search( p )
    if None == action:
      print( "Couldn't find code or method in: " + p )
      return None

    method = action.group( 1 )
    tosearchres = retotag.search( p )
    fromsearchres = refromtag.search( p )
    if "INVITE" == method:
      s[ "tags" ][ "theirs" ] = tosearchres.group( 2 ).strip()
      s[ "tags" ][ "ours" ] = fromsearchres.group( 2 ).strip()
      s[ "touri" ] = tosearchres.group( 1 ).strip()
      s[ "fromuri" ] = fromsearchres.group( 1 ).strip()
      s[ "cseq" ] = int( cseqsearch.search( p ).group( 1 ).strip() )
      s[ "uri" ] = action.group( 2 )
      s[ "via" ] = viaheader.search( p ).group( 1 ).strip()

    return method

  recevivedcode = int( recevivedcode.group( 1 ) )
  if 401 == recevivedcode or 407 == recevivedcode:
    try:
      s[ "tags" ][ "theirs" ] = retotag.search( p ).group( 2 ).strip()
      s[ "auth" ][ "realm" ] = proxyauthrealmauth.search( p ).group( 2 ).strip()
      s[ "auth" ][ "nonce" ] = proxyauthnonce.search( p ).group( 2 ).strip()
      s[ "auth" ][ "qop" ] = qopcheck.search( p ).group( 2 ).strip()
      s[ "auth" ][ "nc" ] = 1
    except:
      print( "Bad things happend whilst parsing packet: " + p )
      print( s )

  elif 200 == recevivedcode:
    s[ "tags" ][ "theirs" ] = retotag.search( p ).group( 2 ).strip()

    cs = contentlengthsearch.search( p )
    if None != cs and  int( cs.group( 1 ) ) > 0:
      s[ "body" ] = p[ p.find( "\r\n\r\n" ): ]

  return recevivedcode

# Return host, port, session
def getremoteaudiohostport( s ):

  return ( sdpaudioipsearch.search( s[ "body" ] ).group( 1 ).strip(),
          int( sdpaudioportsearch.search( s[ "body" ] ).group( 1 ).strip() ),
          int( sdpsessionsearch.search( s[ "body" ] ).group( 2 ).strip() ) )
