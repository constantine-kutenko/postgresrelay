#!/usr/bin/python3

import os
import sys
import time
import json
import yaml
import socket
import select
import struct
import logging
from datetime import datetime
from signal import signal, SIGINT
import queryfilter

VERSION = '0.0.1'

NET_MSG_SIZE = 8192
MAX_CONNECTIONS = 5
delay = 0.0002


def handler(signal_received, frame) -> None:
    """ Handler for correct process termination """
    query_log_file.close()
    log.warning("SIGINT or CTRL-C detected. Exiting gracefully")
    sys.exit(0)


class Relay:
    def __init__(self, local_addr: str, local_port: int, remote_addr: str, remote_port: int) -> None:
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.query_log_file = query_log_file
        self.client_addr = () # A tuple for storing clients' address and port number
        self.sockets = [] # List of all sockets
        self.sockets_deleted = [] # List of removed sockets
        self.tunnel = {} # A dictionary that represents association between a client and a PostgreSQL connection
        self.listconn = [] # List of connection
        self.client_sockets = [] # List of client sockets

        self.relay = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.relay.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.relay.bind((self.local_addr, self.local_port))
        except socket.error as e:
            log.error("Could not bind %s:%s due to: %s" % (self.local_addr, self.local_port, e.strerror))
            sys.exit(1)
        self.relay.listen(MAX_CONNECTIONS)


    def listen(self) -> None:
        """ Listener for incoming clients' connections """
        log.info("Listening on %s:%s..." % (self.local_addr, self.local_port))
        print()
        self.sockets.append(self.relay)

        while True:
            time.sleep(delay)
            read_sockets, _, _ = select.select(self.sockets, [], [])
            for ssock in read_sockets:
                if ssock == self.relay:
                    # Accept incoming connection form a client
                    client_sock, client_address = self.relay.accept()
                    log.info("Client %s:%s connected" % (client_address[0], client_address[1]))
                    self.client_sockets.append(client_sock)
                    # Create a respective connection to a remote PostgreSQL instance
                    pgconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    try:
                        pgconn.connect((remote_addr, remote_port))
                    except Exception as e:
                        log.error("Could not connect to %s:%s due to: %s" % (remote_addr, remote_port ,e))

                    if pgconn:
                        log.info("Established connection to %s:%s" % (remote_addr, remote_port))
                        # Register a new client socket
                        self.client_sockets.append((client_sock,''))
                        self.sockets.append(client_sock)
                        self.sockets.append(pgconn)
                        self.tunnel[client_sock] = pgconn
                        self.tunnel[pgconn] = client_sock
                    else:
                        # If connection to the backend was not established, close client's socket
                        log.warning("Connection to %s:%s cannot be established" % (remote_addr, remote_port))
                        client_sock.close()
                        log.warning("Client connection %s:%s has been closed" % (client_address[0], client_address[1]))
                    break
                # Read data from the socket and get timestamp when it's received
                try:
                    data = ssock.recv(NET_MSG_SIZE)
                    data_starttime = datetime.now()
                except socket.error as e:
                    log.error("Could not receive data due to: %s" % e.strerror)
                finally:
                    pass

                if len(data) == 0:
                    # Close connections if no data received
                    self.connection_close(ssock, client_address[0], client_address[1])
                    break
                else:
                    # Process data received from clients and the backend
                    if ssock in self.client_sockets:
                        # Process messages from clients
                        log.debug("Client %s:%s sent: %s" % (client_address[0], client_address[1], data))
                        packet = (ssock, data, data_starttime, client_address)
                        self.parse(packet)
                    else:
                        # Process messages from the backend
                        # log.debug("Backend %s:%s sent: %s" % (remote_addr, remote_port, data))
                        pass
                    # If client connection is not closed, send the data to the respective endpoint of the tunnel
                    if ssock not in self.sockets_deleted:
                        self.tunnel[ssock].send(data)


    def parse(self, packet: tuple) -> None:
        """ Parser for raw byte data received form a client """
        log.debug("*** BEGIN PARSING DATA ***")
        username = ''
        query = ''
        connection = packet[0]
        data = packet[1]
        data_starttime  = packet[2]
        client_address  = packet[3]

        # Display all packages received from a client
        log.debug("Client %s:%s sent: %s" % (client_address[0], client_address[1], data))
        # Get type of packet
        message_header = data[0:1]

        if message_header == b'Q':
            # A packet that has first byte as b'Q' and the last one as b'\x00' (zero byte) is considered as containing an SQL statement.
            log.debug("Data contains an SQL statement (Q)")
            
            #
            # If data (query) contains certain keywords, consider such a query as ancillary and do not parse
            # if self.is_ancillary(data):
            #     return None
            #

            # Remove the header and zero byte
            query = data[5:-2].decode('utf-8')
        elif message_header == b'P':
            # A packet that has first byte as b'P' and the last one as b'\x00' (zero byte) is considered as containing an SQL statement.
            log.debug("Data contains an SQL statement (P)")
            # Remove header b'P' and ending b'\x00' from data
            query = data[6:]
            # As query statement ends with b'\x00', everything after can be filtered out
            query_structure = struct.unpack(str(len(query)) + 'c', query)
            query_bytes = b''
            for item in query_structure:
                if item != b'\x00':
                    query_bytes = query_bytes + item
                else:
                    break
            query = query_bytes.decode()
        elif message_header == b'R':
            # A packet that has first byte as b'R' is considered as one that contains connection parameters
            log.debug("Data received contains an authentication parameter ('R')")
            message = data[data.find(b'session_authorization') + 22:]
            index = message.find(b'\x00')
            username = message[:index].decode()
            # Create mapping for connection and the respective username
            if (packet[0], username) not in self.listconn and username != '':
                self.listconn.append((packet[0], username))
                log.debug("Added mapping for %s:%s" % (packet[0], username))
            log.debug("Username defined as %s" % username)
            # Check whether a user is in the list of users that are allowed to connect
            if not self.is_user_valid(username):
                # Send a response to the client to notify that credentials provided have not been accepted
                connection.send(self.auth_response(username))
                self.sockets_deleted.append(connection)
                # Close connections
                self.connection_close(connection, client_address[0], client_address[1])
        elif message_header == b'\x00':
            # A packet that has first byte as b'\x00' is considered as one that contains connection parameters
            log.debug("Data contains an authentication parameter (x00)")
            if data[0:8] == b'\x00\x00\x00Q\x00\x03\x00\x00' or data[0:8] == b'\x00\x00\x00u\x00\x03\x00\x00' or data[0:8] == b'\x00\x00\x00k\x00\x03\x00\x00' or data[0:8] == '\x00\x00\x00x\x00\x03\x00\x00':
                log.debug("Authentication statement has been detected")
                elements = data[8:-2].split(b"\x00")
                username = elements[1].decode()
                if (connection, username) not in self.listconn and username != '':
                    self.listconn.append((connection, username))
                    log.debug("Added mapping for %s:%s" % (packet[0], username))
            else:
                # Second attempt to extract username from data
                if b'user' in data:
                    elements = data[8:-2].split(b"\x00")
                    username = elements[1].decode()
                if (connection, username) not in self.listconn and username != '':
                    self.listconn.append((connection, username))
                    log.debug("Added mapping for %s:%s" % (packet[0], username))
            log.debug("Username defined as %s" % username)
            # Check whether a user is in the list of users that are allowed to connect
            if not self.is_user_valid(username):
                # Send a response to the client to notify that credentials provided have not been accepted
                connection.send(self.auth_response(username))
                # Close connection
                self.sockets_deleted.append(connection)
                self.connection_close(connection, client_address[0], client_address[1])
        else:
            # Packet doesn't contain either connection parameters or SQL statements
            log.debug("Data has not been recognized")
        # Get a username for the respective connection (socket)
        for item in self.listconn:
            if item[0] == connection:
                username = item[1]
        # Write a query to the log files
        if query != '' and username != '':
            log.debug("User: \"%s\", query: \"%s\"" % (username, query))
            # Compose a log entry as a JSON string
            data_starttime_timestamp = str(datetime.timestamp(data_starttime))
            data_starttime = str(data_starttime)
            client = client_address[0] + ":" + str(client_address[1])
            # A log entry in ProxySQL format
            logentry = json.dumps({
                "client": client,
                "digest": "null",
                "duration_us": 0,
                "endtime": data_starttime,
                "endtime_timestamp_us": data_starttime_timestamp,
                "event": "null",
                "hostgroup_id": -1,
                "query": query,
                "rows_affected": 0,
                "rows_sent": 0,
                "schemaname": "null",
                "starttime": data_starttime,
                "starttime_timestamp_us": data_starttime_timestamp,
                "thread_id": 0,
                "username": username
            })

            persistent_log_enty = json.dumps({
                "datetime": data_starttime,
                "username": username,
                "query": query.strip('\r\n').replace('  ',' ').replace('\n',' ')
            })

            log.debug("Log entry: %s" % logentry)

            if not self.is_ancillary(data):
                # Writes log entries down to the log file
                query_log_file.write(logentry + '\n')
                query_log_file.flush()

            # Write the same entry to the persistent log file
            persistent_query_log_file.write(persistent_log_enty + '\n')
            persistent_query_log_file.flush()
        log.debug("*** END PARSING DATA ***\n")


    def is_ancillary(self, data: str) -> bool:
        """ Checks whether data contains certain keywords"""
        if query_filter == True:
            for keyword in queryfilter.ANCILLARYQUERY:
                if bytes(keyword, "utf8") in data:
                    log.debug("Query has been filtered out as contains keyword(s): %s" % keyword)
                    log.debug("*** ABORT PARSING DATA ***\n")
                    return True
        return False
    

    def is_user_valid(self, username: str) -> bool:
        """ Checks whether a user is allowed to connect """
        for user_account in config['users']:
            if username == user_account['username']:
                log.debug("User %s has been authenticated" % username)
                return True
        log.debug("User %s is not allowed to connect" % username)
        return False


    def connection_close(self, sock: object, client_address: str, client_port: int) -> None:
        """ Closes client's and backend's connections """
        self.sockets.remove(sock)
        self.sockets.remove(self.tunnel[sock])
        out = self.tunnel[sock]
        self.tunnel[out].close()
        self.tunnel[sock].close()
        del self.tunnel[out]
        del self.tunnel[sock]
        log.info("Client %s:%s disconnected" % (client_address, client_port))
        log.info("Closed connection to %s:%s" % (remote_addr, remote_port))


    def auth_response(self, username: str) -> bytes:
        """ Constructs a message (ErrorResponse) that is sent to the client if provided username is not valid to make connections.
            The message emulates response when a connection is rejected by the backend.
        """
        payload = b'SFATAL\x00VFATAL\x00C28P01\x00Muser "' + username.encode() + b'" is not allowed to make connections through relay\x00Fauth.c\x00L307\x00Rauth_failed\x00\x00'
        payload_len = len(payload) + 4
        resp = b'E' + struct.pack('!I', payload_len)  + payload
        return resp


if __name__ == '__main__':
    # Values are taken from environment variables
    local_addr = os.getenv('LISTEN_ADDR', '0.0.0.0')
    local_port = int(os.getenv('LISTEN_PORT', '8090'))
    remote_addr = os.getenv('REMOTE_ADDR', '127.0.0.1')
    remote_port = int(os.getenv('REMOTE_PORT', '5432'))
    persistent_query_log = os.getenv('PERSISTENT_QUERY_LOG', '/var/log/postgresrelay/postgres_queries.log')
    query_log = os.getenv('QUERY_LOG', '/var/log/postgresrelay/queries.log')
    config_file_path = os.getenv('CONFIG_FILE', '/etc/postgresrelay/config.yaml')
    query_filter = os.getenv('QUERY_FILTER', 'true')
    log_level = os.getenv('LOG_LEVEL', 'info') # info, debug

    if log_level == '' or log_level not in ('info', 'debug'):
        log_level = 'info'

    log = logging.getLogger('stdout')
    logging.basicConfig(format='%(asctime)s [ %(levelname)s ] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    log.setLevel(getattr(logging, log_level.upper()))

    # Open a query log file
    try:
        query_log_file = open(query_log, "a", -1)
    except IOError as ex:
        log.error("Log file cannot be created in %s due to %s" % query_log, ex)
        sys.exit(1)
    
    # Open a persistent query log file
    try:
        persistent_query_log_file = open(persistent_query_log, "a", -1)
    except IOError as ex:
        log.error("Persistent log file cannot be opened in %s due to %s" % persistent_query_log, ex)
        sys.exit(1)
    
    # Load configuration from the configuration file
    try:
        config_file = open(config_file_path)
        config = yaml.safe_load(open(config_file_path))
    except IOError as ex:
        log.error("Configuration file %s cannot be read due to %s" % config_file_path, ex)
        sys.exit(1)

    signal(SIGINT, handler)

    log.info("Starting Postgres Relay v%s. Press CTRL-C to exit" % VERSION)
    log.info("Connections will be forwarded to %s:%s" % (remote_addr, remote_port))
    log.info("Loaded configuration form %s" % config_file_path)
    log.info("All queries will be written to %s" % query_log)
    log.info("Log level: %s" % log_level.upper())

    if query_filter == 'true':
        query_filter = True
        log.info("Ancillary queries' filter is applied")
    elif query_filter == 'false':
        query_filter = False
        log.info("Ancillary queries' filter is disabled")
    else:
        query_filter = True
        log.info("Ancillary queries' filter is applied")

    # Create a relay
    relay = Relay(local_addr, local_port, remote_addr, remote_port)
    relay.listen()
