#!/usr/bin/env python
"""
vncauthproxy - a VNC authentication proxy
"""
#
# Copyright (c) 2010-2013 Greek Research and Technology Network S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

# Daemon files
DEFAULT_LOG_FILE = "/var/log/vncauthproxy/vncauthproxy.log"
DEFAULT_PID_FILE = "/var/run/vncauthproxy/vncauthproxy.pid"

# By default, bind / listen for control connections to TCP *:24999
# (both IPv4 and IPv6)
DEFAULT_LISTEN_ADDRESS = None
DEFAULT_LISTEN_PORT = 24999

# Backlog for the control socket
DEFAULT_BACKLOG = 256

# Timeout for the VNC server connection establishment / RFB handshake
DEFAULT_SERVER_TIMEOUT = 60.0

# Connect retries and delay between retries for the VNC server socket
DEFAULT_CONNECT_RETRIES = 3
DEFAULT_RETRY_WAIT = 0.1

# Connect timeout for the listening sockets
DEFAULT_CONNECT_TIMEOUT = 30

# Port range for the listening sockets
#
# We must take care not to fall into the ephemeral port range,
# this can lead to transient failures to bind a chosen port.
#
# By default, Linux uses 32768 to 61000, see:
# http://www.ncftp.com/ncftpd/doc/misc/ephemeral_ports.html#Linux
# so 25000-30000 seems to be a sensible default.
#
# We also take into account the ports that Ganeti daemons bind to, the port
# range used by DRBD etc.
DEFAULT_MIN_PORT = 25000
DEFAULT_MAX_PORT = 30000

# SSL certificate / key files
DEFAULT_CERT_FILE = "/var/lib/vncauthproxy/cert.pem"
DEFAULT_KEY_FILE = "/var/lib/vncauthproxy/key.pem"

# Auth file
DEFAULT_AUTH_FILE = "/var/lib/vncauthproxy/users"

import os
import sys
import logging
import gevent
import gevent.event
import daemon
import random
import daemon.runner
import hashlib
import re

import rfb

try:
    import simplejson as json
except ImportError:
    import json

from gevent import socket, ssl
from signal import SIGINT, SIGTERM
from gevent.select import select

from lockfile import LockTimeout, AlreadyLocked
# Take care of differences between python-daemon versions.
try:
    from daemon import pidfile as pidlockfile
except ImportError:
    from daemon import pidlockfile

from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler
import geventwebsocket
import base64

from gevent import monkey
monkey.patch_all()

from gevent.pywsgi import WSGIHandler

from hashlib import md5, sha1

logger = None




class LoggedStream(object):
    """File-like stream object that redirects all writes to a logger."""
    def __init__(self, stream, logger, log_level=logging.INFO,
                 description=""):
        self.logger = logger
        self.log_level = log_level
        self.description = description

        self.original_stream = stream

    def write(self, msg):
        for line in msg.rstrip().splitlines():
            self.logger.log(self.log_level, "%s: %s", self.description,
                            line.rstrip())

    def __getattr__(self, name):
        return getattr(self.original_stream, name)


class LoggedStderr(object):
    def __init__(self, logger, log_level=logging.INFO, description="stderr"):
        self.logger = logger
        self.log_level = log_level
        self.description = description

        self.original_stderr = sys.stderr

    def __enter__(self):
        sys.stderr = LoggedStream(sys.stderr, self.logger, self.log_level,
                                  self.description)

    def __exit__(self, type, value, traceback):
        sys.stderr = self.original_stderr




class MyWebSocketHybi(geventwebsocket.websocket.WebSocketHybi):
 
   def __init__(self, *args, **kwargs):
        geventwebsocket.websocket.WebSocketHybi.__init__(self, *args, **kwargs)



   def recv(self,numb):
        data  = geventwebsocket.websocket.WebSocketHybi.receive(self)
        if data != None:
            return base64.b64decode(data)
        else:
            return ''


   def send(self,data):
        data =base64.b64encode(data)
        geventwebsocket.websocket.WebSocketHybi.send(self,data)
    

   def sendall(self,data):
        self.send(data)

class MyWebSocketHandler(WebSocketHandler):
    
    def __init__(self, *args, **kwargs):
        self.status=None
        WSGIHandler.__init__(self, *args, **kwargs)

    def log_error(self, *args, **kwargs):
        with LoggedStderr(logger, logging.DEBUG, "WSGIServer stderr"):
            WebSocketHandler.log_error(self, *args, **kwargs)





    def _handle_hybi(self):
        environ = self.environ
        version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")

        environ['wsgi.websocket_version'] = 'hybi-%s' % version
        self.log_error("THIS IS A TEST LOG ERROR")
        if version not in self.SUPPORTED_VERSIONS:
            self.log_error('400: Unsupported Version: %r', version)
            self.respond(
                '400 Unsupported Version',
                [('Sec-WebSocket-Version', '13, 8, 7')]
            )
            return

        protocol, version = self.request_version.split("/")
        key = environ.get("HTTP_SEC_WEBSOCKET_KEY")

        # check client handshake for validity
        if not environ.get("REQUEST_METHOD") == "GET":
            # 5.2.1 (1)
            self.respond('400 Bad Request')
            return
        elif not protocol == "HTTP":
            # 5.2.1 (1)
            self.respond('400 Bad Request')
            return
        elif float(version) < 1.1:
            # 5.2.1 (1)
            self.respond('400 Bad Request')
            return
        # XXX: nobody seems to set SERVER_NAME correctly. check the spec
        #elif not environ.get("HTTP_HOST") == environ.get("SERVER_NAME"):
            # 5.2.1 (2)
            #self.respond('400 Bad Request')
            #return
        elif not key:
            # 5.2.1 (3)
            self.log_error('400: HTTP_SEC_WEBSOCKET_KEY is missing from request')
            self.respond('400 Bad Request')
            return
        self.websocket = MyWebSocketHybi(self.socket, environ)
        environ['wsgi.websocket'] = self.websocket

        headers = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", base64.b64encode(sha1(key + self.GUID).digest())),
        ]
        self._send_reply("101 Switching Protocols", headers)
        return True



class MyWSGIServer(pywsgi.WSGIServer):

    def log_error(self, *args, **kwargs):
        with LoggedStderr(logger, logging.DEBUG, "WSGIServer stderr"):
            pywsgi.WSGIServer.log_error(self, *args, **kwargs)



class InternalError(Exception):
    """Exception for internal vncauthproxy errors"""
    pass


# Currently, gevent uses libevent-dns for asynchronous DNS resolution,
# which opens a socket upon initialization time. Since we can't get the fd
# reliably, We have to maintain all file descriptors open (which won't harm
# anyway)
class AllFilesDaemonContext(daemon.DaemonContext):
    """DaemonContext class keeping all file descriptors open"""
    def _get_exclude_file_descriptors(self):
        class All:
            def __contains__(self, value):
                return True
        return All()


class VncAuthProxy(gevent.Greenlet):
    """
    Simple class implementing a VNC Forwarder with MITM authentication as a
    Greenlet

    VncAuthProxy forwards VNC traffic from a specified port of the local host
    to a specified remote host:port. Furthermore, it implements VNC
    Authentication, intercepting the client/server handshake and asking the
    client for authentication even if the backend requires none.

    It is primarily intended for use in virtualization environments, as a VNC
    ``switch''.

    """
    id = 1

    def __init__(self, logger, client):
        """
        @type logger: logging.Logger
        @param logger: the logger to use
        @type client: socket.socket
        @param listeners: the client control connection socket

        """
        gevent.Greenlet.__init__(self)
        self.id = VncAuthProxy.id
        VncAuthProxy.id += 1
        self.log = logger
        self.client = client
        # A list of worker/forwarder greenlets, one for each direction
        self.workers = []
        self.sport = None
        self.pool = None
        self.daddr = None
        self.dport = None
        self.server = None
        self.password = None
        self.ws = None
        self.console_type = None
        self.websocket_server = None
        self.no_connection =  True


    def __call__(self,environ,start_response):

        try:
            self.no_connection = False
            self.workers = []
            ws = environ['wsgi.websocket']
            self.ws=ws
            self._client_handshake()
            self._start_forwarding()
        except Exception,e:
            # Any unhandled exception in the previous block
            # is an error and must be logged accordingly
            if not isinstance(e, gevent.GreenletExit):
                self.exception(e)
            raise e
        finally:
            self._cleanup()

    def _start_forwarding(self):

        try:  
            # Bridge both connections through two "forwarder" greenlets.
            # This greenlet will wait until any of the workers dies.
            # Final cleanup will take place in _cleanup().
            dead = gevent.event.Event()
            dead.clear()

            # This callback will get called if any of the two workers dies.
            def callback(g):
                self.debug("Worker %d/%d died", self.workers.index(g),
                           len(self.workers))
                dead.set()

            self.workers.append(gevent.spawn(self._forward,
                                             self.ws, self.server))
            self.workers.append(gevent.spawn(self._forward,
                                             self.server,self.ws))
            for g in self.workers:
                g.link(callback)

            # Wait until any of the workers dies
            self.debug("Waiting for any of %d workers to die",
                       len(self.workers))
            dead.wait()

            # We can go now, _cleanup() will take care of
            # all worker, socket and port cleanup
            self.debug("A forwarder died, our work here is done")
            raise gevent.GreenletExit
        except Exception,e:
            # Any unhandled exception in the previous block
            # is an error and must be logged accordingly
            if not isinstance(e, gevent.GreenletExit):
                self.exception(e)
            if self.console_type == 'wsvnc':
                raise e


    def _cleanup(self):
        """Cleanup everything: workers, sockets, ports

        Kill all remaining forwarder greenlets, close all active sockets,
        return the source port to the pool if applicable, then exit
        gracefully.

        """
        # Make sure all greenlets are dead, then clean them up
        self.debug("Cleaning up %d workers", len(self.workers))
        for g in self.workers:
            g.kill()
        gevent.joinall(self.workers)
        del self.workers

        self.debug("Cleaning up sockets")
        #while self.listeners:
        #    sock = self.listeners.pop().close()
        try:
            if self.server:
                self.server.close()

            if self.client:
                self.client.close()

        
            self.debug("Stoping web socket server")
            if self.websocket_server:
                self.websocket_server.stop()
                self.websocket_server.kill()

            
            self.debug("Closing web socket")
            if self.ws:
                self.ws.close()   
        except Exception as err:
            self.error(err)
        # Reintroduce the port number of the client socket in
        # the port pool, if applicable.
        if not self.pool is None:
            self.pool.append(self.sport)
            self.debug("Returned port %d to port pool, contains %d ports",
                       self.sport, len(self.pool))
       

        self.info("Cleaned up connection, all done")
        if self.console_type == "wsvnc":
            raise gevent.GreenletExit

    def __str__(self):
        return "VncAuthProxy: %d -> %s:%d" % (self.sport, self.daddr,
                                              self.dport)

    def _forward(self, source, dest):
        """
        Forward traffic from source to dest

        @type source: socket
        @param source: source socket
        @type dest: socket
        @param dest: destination socket

        """

        while True:
            d = source.recv(16384)
            if d == '':
                if source == self.client:
                    self.info("Client connection closed")
                else:
                    self.info("Server connection closed")
                break
            dest.sendall(d) 





    def _perform_server_handshake(self):
        """
        Initiate a connection with the backend server and perform basic
        RFB 3.8 handshake with it.

        Return a socket connected to the backend server.

        """
        server = None

        tries = VncAuthProxy.connect_retries
        while tries:
            tries -= 1

            # Initiate server connection
            for res in socket.getaddrinfo(self.daddr, self.dport,
                                          socket.AF_UNSPEC,
                                          socket.SOCK_STREAM, 0,
                                          socket.AI_PASSIVE):
                af, socktype, proto, canonname, sa = res
                try:
                    server = socket.socket(af, socktype, proto)
                except socket.error:
                    server = None
                    continue

                # Set socket timeout for the initial handshake
                server.settimeout(VncAuthProxy.server_timeout)

                try:
                    self.debug("Connecting to %s:%s", *sa[:2])
                    server.connect(sa)
                    self.debug("Connection to %s:%s successful", *sa[:2])
                except socket.error as err:
                    self.debug("Failed to perform sever hanshake, retrying...")
                    server.close()
                    server = None
                    continue

                # We succesfully connected to the server
                tries = 0
                break

            # Wait and retry
            gevent.sleep(VncAuthProxy.retry_wait)

        if server is None:
            raise InternalError("Failed to connect to server")
        
        version = server.recv(1024)
        if not rfb.check_version(version):
            raise InternalError("Unsupported RFB version: %s"
                                % version.strip())

        server.send(rfb.RFB_VERSION_3_8 + "\n")

        res = server.recv(1024)
        types = rfb.parse_auth_request(res)
        if not types:
            raise InternalError("Error handshaking with the server")

        else:
            self.debug("Supported authentication types: %s",
                         " ".join([str(x) for x in types]))

        if rfb.RFB_AUTHTYPE_NONE not in types:
            raise InternalError("Error, server demands authentication")

        server.send(rfb.to_u8(rfb.RFB_AUTHTYPE_NONE))

        # Check authentication response
        res = server.recv(4)
        res = rfb.from_u32(res)

        if res != 0:
            raise InternalError("Authentication error")

        # Reset the timeout for the rest of the session
        server.settimeout(None)

        self.server = server

    def _establish_connection(self):
        client = self.client
        ports = VncAuthProxy.ports

        # Receive and parse a client request.
        response = {
            "source_port": 0,
            "status": "FAILED",
        }
        try:
            # Control request, in JSON:
            #
            # {
            #     "source_port":
            #         <source port or 0 for automatic allocation>,
            #     "destination_address":
            #         <destination address of backend server>,
            #     "destination_port":
            #         <destination port>
            #     "password":
            #         <the password to use to authenticate clients>
            #     "auth_user":
            #         <user for control connection authentication>,
            #      "auth_password":
            #         <password for control connection authentication>,
            #     "console_type":
            #         < type of console connection: vnc or websocketvnc(wsvnc)
            # }
            #
            # The <password> is used for MITM authentication of clients
            # connecting to <source_port>, who will subsequently be
            # forwarded to a VNC server listening at
            # <destination_address>:<destination_port>
            #
            # Control reply, in JSON:
            # {
            #     "source_port": <the allocated source port>
            #     "status": <one of "OK" or "FAILED">
            # }
            #
            buf = client.recv(2048)
            req = json.loads(buf)

            auth_user = req['auth_user']
            auth_password = req['auth_password']
            sport_orig = int(req['source_port'])
            self.daddr = req['destination_address']
            self.dport = int(req['destination_port'])
            self.password = req['password']
            self.console_type=req['console_type']
            

            self.debug("cosnole type is %s" % self.console_type)
            if auth_user not in VncAuthProxy.authdb:
                msg = "Authentication failure: user not found"
                raise InternalError(msg)

            (cipher, authdb_password) = VncAuthProxy.authdb[auth_user]
            if cipher == 'HA1':
                message = auth_user + ':vncauthproxy:' + auth_password
                auth_password = hashlib.md5(message).hexdigest()

            if auth_password != authdb_password:
                msg = "Authentication failure: wrong password"
                raise InternalError(msg)
        except KeyError:
            msg = "Malformed request: %s" % buf
            raise InternalError(msg)
        except InternalError as err:
            self.warn(err)
            response['reason'] = str(err)
            client.send(json.dumps(response))
            client.close()
            raise gevent.GreenletExit
        except Exception as err:
            self.exception(err)
            self.error("Unexpected error")
            client.send(json.dumps(response))
            client.close()
            raise gevent.GreenletExit

        server = None
        pool = None
        sport = sport_orig
        try:
            # If the client has so indicated, pick an ephemeral source port
            # randomly, and remove it from the port pool.
            if sport_orig == 0:
                while True:
                    try:
                        sport = random.choice(ports)
                        ports.remove(sport)
                        break
                    except ValueError:
                        self.debug("Port %d already taken", sport)

                self.debug("Got port %d from pool, %d remaining",
                           sport, len(ports))
                pool = ports

            self.sport = sport
            self.pool = pool
    
            if self.console_type == 'vnc':
                self.listeners = get_listening_sockets(sport)
            self._perform_server_handshake()

            self.info("New forwarding: %d (client req'd: %d) -> %s:%d",
                        sport, sport_orig, self.daddr, self.dport)
            response = {"source_port": sport,
                        "status": "OK"}
        except IndexError:
            self.error(("FAILED forwarding, out of ports for [req'd by "
                          "client: %d -> %s:%d]"),
                         sport_orig, self.daddr, self.dport)
            raise gevent.GreenletExit
        except InternalError as err:
            self.error(err)
            self.error(("FAILED forwarding: %d (client req'd: %d) -> "
                          "%s:%d"), sport, sport_orig, self.daddr, self.dport)
            if pool:
                pool.append(sport)
                self.debug("Returned port %d to pool, %d remanining",
                             sport, len(pool))
            if server:
                server.close()
            raise gevent.GreenletExit
        except Exception as err:
            self.exception(err)
            self.error("Unexpected error")
            self.error(("FAILED forwarding: %d (client req'd: %d) -> "
                          "%s:%d"), sport, sport_orig, self.daddr, self.dport)
            if pool:
                pool.append(sport)
                self.debug("Returned port %d to pool, %d remanining",
                             sport, len(pool))
            if server:
                server.close()
            raise gevent.GreenletExit
        finally:
            client.send(json.dumps(response))
            client.close()

    def _client_handshake(self):
        """
        Perform handshake/authentication with a connecting client

        Outline:
        1. Client connects
        2. We fake RFB 3.8 protocol and require VNC authentication
           [processing also supports RFB 3.3]
        3. Client accepts authentication method
        4. We send an authentication challenge
        5. Client sends the authentication response
        6. We check the authentication

        Upon return, self.client socket is connected to the client.

        """
        self.ws.send(rfb.RFB_VERSION_3_8 + "\n")
        client_version_str = self.ws.recv(1024)
        client_version = rfb.check_version(client_version_str)
        if not client_version:
            self.error("Invalid version: %s", client_version_str)
            raise gevent.GreenletExit

        # Both for RFB 3.3 and 3.8
        self.debug("Requesting authentication")
        auth_request = rfb.make_auth_request(rfb.RFB_AUTHTYPE_VNC,
                                             version=client_version)
        self.ws.send(auth_request)

        # The client gets to propose an authtype only for RFB 3.8
        if client_version == rfb.RFB_VERSION_3_8:
            res = self.ws.recv(1024)
            type = rfb.parse_client_authtype(res)
            if type == rfb.RFB_AUTHTYPE_ERROR:
                self.warn("Client refused authentication: %s", res[1:])
            else:
                self.debug("Client requested authtype %x", type)

            if type != rfb.RFB_AUTHTYPE_VNC:
                self.error("Wrong auth type: %d", type)
                self.ws.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
                raise gevent.GreenletExit

        # Generate the challenge
        challenge = os.urandom(16)
        self.ws.send(challenge)
        response = self.ws.recv(1024)
        if len(response) != 16:
            self.error("Wrong response length %d, should be 16", len(response))
            raise gevent.GreenletExit

        if rfb.check_password(challenge, response, self.password):
            self.debug("Authentication successful")
        else:
            self.warn("Authentication failed")
            self.ws.send(rfb.to_u32(rfb.RFB_AUTH_ERROR))
            raise gevent.GreenletExit

        # Accept the authentication
        self.ws.send(rfb.to_u32(rfb.RFB_AUTH_SUCCESS))

   
    
    def _proxy(self):

        if self.console_type == 'vnc':
            self.info("got the connection will be a normal tcp socket connection")
	    self._dproxy() #call old proxy and continue as before
        else:
            server = MyWSGIServer(("", self.sport), self,
                handler_class=MyWebSocketHandler,keyfile=DEFAULT_KEY_FILE,certfile=DEFAULT_CERT_FILE,server_side=True)
            self.websocket_server=server
            self.websocket_server.start()
            gevent.sleep(DEFAULT_CONNECT_TIMEOUT)
            if self.no_connection == True :
                self.info("No incoming connection for %s seconds.Performing cleaup" % DEFAULT_CONNECT_TIMEOUT)
                self._cleanup()
        
    
    
    
    def _dproxy(self):
        try:
            self.workers = []
            self.info("Waiting for a client to connect at %s",
                      ", ".join(["%s:%d" % s.getsockname()[:2]
                                 for s in self.listeners]))
            rlist, _, _ = select(self.listeners, [], [],
                          timeout=VncAuthProxy.connect_timeout)
            if not rlist:
                self.info("Timed out, no connection after %d sec",
                          VncAuthProxy.connect_timeout)
                raise gevent.GreenletExit

            for sock in rlist:
                self.client, addrinfo = sock.accept()
                self.info("Connection from %s:%d", *addrinfo[:2])

                # Close all listening sockets, we only want a one-shot
                # connection from a single client.
                while self.listeners:
                    sock = self.listeners.pop().close()
                break
            
            #we will just treat tcp socket as if it was websocket
            self.ws=self.client
            
            # Perform RFB handshake with the client.
            self._client_handshake()
            self._start_forwarding()
        except Exception as err:
            # Any unhandled exception in the previous block
            # is an error and must be logged accordingly
            self.exception(err)
            self.error("Unexpected error")
            raise err
        finally:
            self._cleanup()
        

    def _run(self):
        self._establish_connection()
        self._proxy()

# Logging support inside VncAuthproxy
# Wrap all common logging functions in logging-specific methods
for funcname in ["info", "debug", "warn", "error", "critical",
                 "exception"]:

    def gen(funcname):
        def wrapped_log_func(self, *args, **kwargs):
            func = getattr(self.log, funcname)
            func("[C%d] %s" % (self.id, args[0]), *args[1:], **kwargs)
        return wrapped_log_func
    setattr(VncAuthProxy, funcname, gen(funcname))


def fatal_signal_handler(signame):
    logger.info("Caught %s, will raise SystemExit", signame)
    raise SystemExit


def get_listening_sockets(sport, saddr=None, reuse_addr=False):
    sockets = []

    # Use two sockets, one for IPv4, one for IPv6. IPv4-to-IPv6 mapped
    # addresses do not work reliably everywhere (under linux it may have
    # been disabled in /proc/sys/net/ipv6/bind_ipv6_only).
    for res in socket.getaddrinfo(saddr, sport, socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res
        try:
            s = None
            s = socket.socket(af, socktype, proto)

            if af == socket.AF_INET6:
                # Bind v6 only when AF_INET6, otherwise either v4 or v6 bind
                # will fail.
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

            if reuse_addr:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind(sa)
            s.listen(1)
            sockets.append(s)
            logger.debug("Listening on %s:%d", *sa[:2])
        except socket.error as err:
            logger.error("Error binding to %s:%d: %s", sa[0], sa[1], err[1])
            if s:
                s.close()
            while sockets:
                sock = sockets.pop().close()

            # Make sure we fail immediately if we cannot get a socket
            raise InternalError(err)

    return sockets


def parse_auth_file(auth_file):
    supported_ciphers = ('cleartext', 'HA1', None)
    regexp = re.compile(r'^\s*(?P<user>\S+)\s+({(?P<cipher>\S+)})?'
                         '(?P<pass>\S+)\s*$')

    users = {}
    try:
        with open(auth_file) as f:
            lines = [l.strip() for l in f.readlines()]

            for line in lines:
                if not line or line.startswith('#'):
                    continue

                m = regexp.match(line)
                if not m:
                    raise InternalError("Invaild entry in auth file: %s"
                                        % line)

                user = m.group('user')
                cipher = m.group('cipher')
                if cipher not in supported_ciphers:
                    raise InternalError("Unsupported cipher in auth file: "
                                        "%s" % line)

                password = (cipher, m.group('pass'))

                if user in users:
                    raise InternalError("Duplicate user entry in auth file")

                users[user] = password
    except IOError as err:
        logger.error("Couldn't read auth file")
        raise InternalError(err)

    if not users:
        logger.warn("No users specified.")

    return users


def parse_arguments(args):
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      help="Enable debugging information")
    parser.add_option("--log", dest="log_file",
                      default=DEFAULT_LOG_FILE,
                      metavar="FILE",
                      help=("Write log to FILE (default: %s)" %
                            DEFAULT_LOG_FILE))
    parser.add_option('--pid-file', dest="pid_file",
                      default=DEFAULT_PID_FILE,
                      metavar='PIDFILE',
                      help=("Save PID to file (default: %s)" %
                            DEFAULT_PID_FILE))
    parser.add_option("--listen-address", dest="listen_address",
                      default=DEFAULT_LISTEN_ADDRESS,
                      metavar="LISTEN_ADDRESS",
                      help=("Address to listen for control connections"
                            "(default: *)"))
    parser.add_option("--listen-port", dest="listen_port",
                      default=DEFAULT_LISTEN_PORT,
                      metavar="LISTEN_PORT",
                      help=("Port to listen for control connections"
                            "(default: %d)" % DEFAULT_LISTEN_PORT))
    parser.add_option("--server-timeout", dest="server_timeout",
                      default=DEFAULT_SERVER_TIMEOUT, type="float",
                      metavar="N",
                      help=("Wait for N seconds for the VNC server RFB "
                            "handshake (default %s)" % DEFAULT_SERVER_TIMEOUT))
    parser.add_option("--connect-retries", dest="connect_retries",
                      default=DEFAULT_CONNECT_RETRIES, type="int",
                      metavar="N",
                      help=("Retry N times to connect to the "
                            "server (default: %d)" %
                            DEFAULT_CONNECT_RETRIES))
    parser.add_option("--retry-wait", dest="retry_wait",
                      default=DEFAULT_RETRY_WAIT, type="float",
                      metavar="N",
                      help=("Wait N seconds before retrying "
                            "to connect to the server (default: %s)" %
                            DEFAULT_RETRY_WAIT))
    parser.add_option("--connect-timeout", dest="connect_timeout",
                      default=DEFAULT_CONNECT_TIMEOUT, type="int",
                      metavar="N",
                      help=("Wait N seconds for a client "
                            "to connect (default: %d)"
                            % DEFAULT_CONNECT_TIMEOUT))
    parser.add_option("-p", "--min-port", dest="min_port",
                      default=DEFAULT_MIN_PORT, type="int", metavar="MIN_PORT",
                      help=("The minimum port number to use for automatically-"
                            "allocated ephemeral ports (default: %s)" %
                            DEFAULT_MIN_PORT))
    parser.add_option("-P", "--max-port", dest="max_port",
                      default=DEFAULT_MAX_PORT, type="int", metavar="MAX_PORT",
                      help=("The maximum port number to use for automatically-"
                            "allocated ephemeral ports (default: %s)" %
                            DEFAULT_MAX_PORT))
    parser.add_option('--no-ssl', dest="no_ssl",
                      default=False, action='store_true',
                      help=("Disable SSL/TLS for control connections "
                            "(default: False"))
    parser.add_option('--cert-file', dest="cert_file",
                      default=DEFAULT_CERT_FILE,
                      metavar='CERTFILE',
                      help=("SSL certificate (default: %s)" %
                            DEFAULT_CERT_FILE))
    parser.add_option('--key-file', dest="key_file",
                      default=DEFAULT_KEY_FILE,
                      metavar='KEYFILE',
                      help=("SSL key (default: %s)" %
                            DEFAULT_KEY_FILE))
    parser.add_option('--auth-file', dest="auth_file",
                      default=DEFAULT_AUTH_FILE,
                      metavar='AUTHFILE',
                      help=("Authentication file (default: %s)" %
                            DEFAULT_AUTH_FILE))

    (opts, args) = parser.parse_args(args)

    if args:
        parser.print_help()
        sys.exit(1)

    return opts


def main():
    """Run the daemon from the command line"""

    opts = parse_arguments(sys.argv[1:])

    # Create pidfile
    pidf = pidlockfile.TimeoutPIDLockFile(opts.pid_file, 10)

    # Initialize logger
    lvl = logging.DEBUG if opts.debug else logging.INFO

    global logger
    logger = logging.getLogger("vncauthproxy")
    logger.setLevel(lvl)
    formatter = logging.Formatter(("%(asctime)s %(module)s[%(process)d] "
                                   " %(levelname)s: %(message)s"),
                                  "%Y-%m-%d %H:%M:%S")
    handler = logging.FileHandler(opts.log_file)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Become a daemon:
    # Redirect stdout and stderr to handler.stream to catch
    # early errors in the daemonization process [e.g., pidfile creation]
    # which will otherwise go to /dev/null.
    daemon_context = AllFilesDaemonContext(
        pidfile=pidf,
        umask=0022,
        stdout=handler.stream,
        stderr=handler.stream,
        files_preserve=[handler.stream])

    # Remove any stale PID files, left behind by previous invocations
    if daemon.runner.is_pidfile_stale(pidf):
        logger.warning("Removing stale PID lock file %s", pidf.path)
        pidf.break_lock()

    try:
        daemon_context.open()
    except (AlreadyLocked, LockTimeout):
        logger.critical(("Failed to lock PID file %s, another instance "
                         "running?"), pidf.path)
        sys.exit(1)
    logger.info("Became a daemon!")

    # A fork() has occured while daemonizing,
    # we *must* reinit gevent
    gevent.reinit()

    # Catch signals to ensure graceful shutdown,
    #
    # Uses gevent.signal so the handler fires even during
    # gevent.socket.accept()
    gevent.signal(SIGINT, fatal_signal_handler, "SIGINT")
    gevent.signal(SIGTERM, fatal_signal_handler, "SIGTERM")

    # Init ephemeral port pool
    ports = range(opts.min_port, opts.max_port + 1)

    # Init VncAuthProxy class attributes
    VncAuthProxy.server_timeout = opts.server_timeout
    VncAuthProxy.connect_retries = opts.connect_retries
    VncAuthProxy.retry_wait = opts.retry_wait
    VncAuthProxy.connect_timeout = opts.connect_timeout
    VncAuthProxy.ports = ports

    try:
        VncAuthProxy.authdb = parse_auth_file(opts.auth_file)
    except InternalError as err:
        logger.critical(err)
        sys.exit(1)
    except Exception as err:
        logger.exception(err)
        logger.error("Unexpected error")
        sys.exit(1)

    try:
        sockets = get_listening_sockets(opts.listen_port, opts.listen_address,
                                        reuse_addr=True) 
    except InternalError as err:
        logger.critical("Error binding control socket")
        sys.exit(1)
    except Exception as err:
        logger.exception(err)
        logger.error("Unexpected error")
        sys.exit(1)

    while True:
        try:
            client = None
            rlist, _, _ = select(sockets, [], [])
            for ctrl in rlist:
                client, _ = ctrl.accept()
                logger.info("no ssl option is %s"% opts.no_ssl)
                if not opts.no_ssl:
                    client = ssl.wrap_socket(client,
                                             server_side=True,
                                             keyfile=opts.key_file,
                                             certfile=opts.cert_file,
                                             ssl_version=ssl.PROTOCOL_TLSv1)
                logger.info("New control connection")

                VncAuthProxy.spawn(logger, client)
            continue
        except Exception, e:
            logger.exception(e)
            logger.error("Unexpected error")
            if client:
                client.close()
            continue
        except SystemExit:
            break

    logger.info("Closing control sockets")
    while sockets:
        sock = sockets.pop()
        sock.close()

    daemon_context.close()
    sys.exit(0)

if __name__=="__main__":
    main()
