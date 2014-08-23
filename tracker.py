__author__ = 'Adam Gensler'

from dxxtoolkit import *
from my_functions import *
import argparse
import json
import logging.handlers
import select
import socket
import threading
import time


def get_external_ip():
    logger.debug('entered get_external_ip')

    # Determine this tracker's external IP address
    try:
        # TODO: make this a configurable command line option
        ip_addr = socket.gethostbyname('retro-tracker.game-server.cc')
        logger.debug('External ip: {0}'.format(ip_addr))
        return ip_addr
    except socket.error:
        logger.exception('Unable to resolve external_ip')
        return None


def check_version(major, minor, micro):
    logger.debug('entered check_version')
    if (major, minor, micro) != (MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION):
        logger.error('Version mismatch')
        return False
    else:
        logger.debug('Version match')
        return True


def active_game_check(key):
    logger.debug('entered active_game_check')

    # Make sure we actually have a game active from this ip:port
    if key in active_games:
        return True
    else:
        logger.error('Game hosted by {0} not found in '
                     'active_games'.format(key))
        return False


def determine_variant(versions):
    logger.debug('entered determine_variant')

    if (versions == (0, 58, 1, 0)):
        # dxx rebirth 0.58.1
        return GAME_VARIANTS[0]

    if (versions == (0, 58, 1, 2130) or versions == (0, 58, 1, 2131)):
        # dxx retro 1.3
        return GAME_VARIANTS[1]

    return False


def register_request(data, address):
    logger.debug('entered register_request')

    game_data = dxx_process_register(data)
    if not game_data:
        logger.error('Unable to handle register request, no data')
        return False

    # make sure we're talking the same tracker protocol version
    if TRACKER_PROTOCOL_VERSION != game_data['tracker_ver']:
        logger.error('Received register with incorrect tracker '
                     'version, dropping')
        return False

    # check the game version, make sure we can support it
    if not check_version(game_data['release_major'],
                         game_data['release_minor'],
                         game_data['release_micro']):
        logger.error('Unknown game version, dropping')
        return False

    # Check to make sure the port is actually there. Check just over port 1024
    # and higher. Ports 1023 and below require root access on most platforms
    # and people shouldn't be running the game as root
    if game_data['port'] < 1024:
        logger.error('Port value under 1024, dropping')
        return False

    key = '{0}:{1}'.format(address[0], game_data['port'])

    # Perform a duplicate game check to make sure we don't already have a game
    # registered via this ip:port, but with a different game_id.
    if active_game_check(key):
        if active_games[key]['game_id'] != game_data['game_id']:
            logger.debug('Game ID {0} hosted by {1} is stale.'.format(
                active_games[key]['game_id'], key))
            stale_game(key)
        else:
            logger.debug('Game ID {0} hosted by {1} is already '
                         'registered.'.format(active_games[key]['game_id'],
                                              key))
            return True

    # If we've made it here this is a new game so add it to the
    # active_games dict.
    active_games[key] = {}
    active_games[key].update(NEW_GAME_TEMPLATE)
    active_games[key].update(game_data)
    active_games[key]['ip'] = address[0]

    # send register ack, then send it two more times just in case
    dxx_send_register_response(address, listen_socket)
    for i in range(1, 3):
        threading.Timer(i * 0.025, dxx_send_register_response,
                        [address, listen_socket]).start()

    # send a game_info_lite request
    game_info_request(0, key)

    logger.debug('Added new game ID {0} hosted by {1} to '
                 'active_games: \n{2}'.format(active_games[key]['game_id'],
                                              key,
                                              active_games[key]))


def unregister_request(data, address):
    logger.debug('entered unregister_request')

    game_data = dxx_process_unregister(data)
    if not game_data:
        logger.debug('Unable to handle unregister request, no data')
        return False

    # The game does not use the same socket to communicate with the Tracker
    # that it uses to communicate with other clients. The keys used by this
    # Tracker to index the games is ip:port, typically of the sender of a
    # received packet. Unfortunately because of this socket difference the
    # ip:port of the Unregister message received by the Tracker will most
    # likely not match the ip:port stored in the active_games dictionary.
    # As such, we need to loop through all the active games, look for the
    # game_id specified in the unregister message, check it against the IP
    # address the unregister game from and hope for the best.
    for i in active_games:
        if ((active_games[i]['game_id'] == game_data['game_id']) and
                (active_games[i]['ip'] == address[0])):
            logger.info('Unregistering game ID {0} hosted by {1}'.format(
                game_data['game_id'], i))
            stale_game(i)
            return True
    return False


def game_info_request(req_type, key):
    logger.debug('entered game_info_request')

    # Make sure we actually have a game active from this ip:port
    if not active_game_check(key):
        return False

    address = (active_games[key]['ip'], active_games[key]['port'])

    dxx_send_game_info_request(active_games[key]['version'], req_type,
                               active_games[key]['netgame_proto'],
                               address, listen_socket)

    active_games[key]['pending_info_reqs'] += 1


def game_info_response(data, address):
    logger.debug('entered game_info_response')

    key = '{0}:{1}'.format(address[0], address[1])

    # Make sure we actually have a game active from this ip:port
    if not active_game_check(key):
        return False

    game_data = dxx_process_game_info_response(data)
    if not game_data:
        logger.debug('Unable to handle game_info response')
        return False

    # Make sure we actually have a request pending before processing the data
    if active_games[key]['pending_info_reqs'] == 0:
        logger.error('Received info response from {0} when no info '
                     'response was pending'.format(key))
        return False
    else:
        active_games[key]['pending_info_reqs'] = 0

    # If we make it here, we should update the active_games dict with the
    # information we got back from this game_info_response
    active_games[key].update(game_data)

    # If we don't have a start time recorded for this game, and, if the game
    # has actually started playing, go ahead and record the (approx) start time
    if (active_games[key]['start_time'] == 0 and
            active_games[key]['status'] == 1):
        active_games[key]['start_time'] = time.time()

    # Check whether or not this game has already been confirmed by an info_lite
    # response. If not, make it as confirmed and then return, even if this is
    # a detailed response with data we could use. This will prevent game state
    # mismatches when Rebirth games are hosted, quit, and rehosted when info
    # requests are in-flight over the network. We'll get detailed info from
    # those games on the next pass around.
    if active_games[key]['confirmed'] == 0:
        active_games[key]['confirmed'] = 1
        logger.debug('Confirmed game ID {0} hosted by {1}'.format(
            active_games[key]['game_id'], key))

        # Setup a udp relay so this game can appear on the Main tracker as well
        # but only do it if we didn't learn this game from the Main tracker to
        # begin with, that would be bad.
        if active_games[key]['main_tracker'] == 0:
            setup_udp_relay(key)

        return True

    # If the opcode for this game was 3, this is a full game info response
    if data[0] == OPCODE_GAME_INFO_RESPONSE:

        # determine if we're talking to Rebirth or Retro
        if 'variant' not in active_games[key]:
            versions = (active_games[key]['release_major'],
                        active_games[key]['release_minor'],
                        active_games[key]['release_micro'],
                        active_games[key]['netgame_proto'])
            active_games[key]['variant'] = determine_variant(versions)

        if active_games[key]['variant'] == GAME_VARIANTS[0]:
            logger.debug('This appears to be a rebirth game')
            active_games[key].update(NON_RETRO_GAME_TEMPLATE)

        # Capture approximate player join times
        for i in range(0, 8):
            player_name = 'player{0}name'.format(i)
            player_time = 'player{0}time'.format(i)
            if player_time not in active_games[key]:
                active_games[key][player_time] = 0
            elif (active_games[key][player_time] == 0 and
                    active_games[key][player_name] and
                    active_games[key]['start_time']):
                active_games[key][player_time] = time.time()
                logger.debug('Player {0} appears to have '
                             'just joined'.format(i))

        # note that we've got detailed data
        active_games[key]['detailed'] = 1

    logger.debug('Updated game ID {0} hosted by {1} in '
                 'active_games: \n{2}'.format(active_games[key]['game_id'],
                                              key, active_games[key]))


def version_deny(address):
    logger.debug('entered version_deny')

    key = '{0}:{1}'.format(address[0], address[1])

    # Make sure we actually have a game active from this ip:port
    if not active_game_check(key):
        return False

    game_data = dxx_process_version_deny(data)
    if not game_data:
        logger.debug('Unable to handle version deny, no data')
        return False

    # check the game version, make sure we can support it
    if not check_version(game_data['release_major'],
                         game_data['release_minor'],
                         game_data['release_micro']):
        logger.error('Unknown game version, dropping')
        return False

    active_games[key]['netgame_proto'] = game_data['netgame_proto']

    logger.debug('Netgame protocol for game ID {0} host by {1} '
                 'set to {2}: '.format(active_games[key]['game_id'],
                                       key,
                                       active_games[key]['netgame_proto']))


def game_list_request(data, address):
    logger.debug('entered game_list_request')

    game_data = dxx_process_game_list_request(data)
    if not game_data:
        logger.error('Unable to handle game list request, no data')
        return False

    for i in active_games:
        # only return confirmed games that are the same
        # version (i.e. D1 or D2) to the person requesting the list
        if (active_games[i]['confirmed'] == 1 and
                active_games[i]['version'] == game_data['version']):

            # determine which IP address to return to client
            ip_addr = active_games[i]['ip']
            for s in int_ip_list:
                if s == ip_addr:
                    logger.debug('Internal host, attempting to '
                                 'swap IP address')
                    if external_ip:
                        ip_addr = external_ip

            # build the response dict to send to dxx_send_game_list_response
            response_data = {}
            response_data['ip'] = ip_addr
            response_data['port'] = active_games[i]['port']
            response_data['game_id'] = active_games[i]['game_id']
            response_data['release_major'] = active_games[i]['release_major']
            response_data['release_minor'] = active_games[i]['release_minor']
            response_data['release_micro'] = active_games[i]['release_micro']
            response_data['netgame_name'] = active_games[i]['netgame_name']
            response_data['mission_title'] = active_games[i]['mission_title']
            response_data['mission_name'] = active_games[i]['mission_name']
            response_data['level_num'] = active_games[i]['level_num']
            response_data['mode'] = active_games[i]['mode']
            response_data['refuse_players'] = active_games[i]['refuse_players']
            response_data['difficulty'] = active_games[i]['difficulty']
            response_data['status'] = active_games[i]['status']
            response_data['players'] = active_games[i]['players']
            response_data['max_players'] = active_games[i]['max_players']
            response_data['flags'] = active_games[i]['flags']

            dxx_send_game_list_response(response_data, address, listen_socket)


def game_list_response(data, version):
    logger.debug('entered game_list_response')

    game_data = dxx_process_game_list_response(data)
    if not game_data:
        logger.error('Unable to handle game list response, no data')
        return False

    # Track the last time we got a game list response from the main tracker.
    # This is used by the webUI to let players know when the last time I heard
    # from the main tracker, giving some (crude) sense of whether or not it is
    # up.
    global last_list_response_time
    last_list_response_time = int(time.time())

    if game_data['ip'] == external_ip:
        logger.debug('Received relayed game hosted by {0}:{1} from Main '
                     'tracker, ignoring'.format(game_data['ip'],
                                                game_data['port']))
        return False

    # check the game version, make sure we can support it
    if not check_version(game_data['release_major'],
                         game_data['release_minor'],
                         game_data['release_micro']):
        logger.error('Received game list response with incorrect '
                     'game version, dropping')
        return False

    # make sure there's an actual port number here
    if game_data['port'] < 1024:
        logger.error('Port value under 1024, dropping')
        return False

    key = '{0}:{1}'.format(game_data['ip'], game_data['port'])

    # Perform a duplicate game check to make sure we don't already have a game
    # registered via this ip:port, but with a different game_id.
    if key in active_games:
        if active_games[key]['game_id'] != game_data['game_id']:
            logger.debug('Game ID {0} hosted by {1} is stale.'.format(
                active_games[key]['game_id'], key))
            stale_game(key)
        else:
            logger.debug('Game ID {0} hosted by {1} is already '
                         'registered.'.format(active_games[key]['game_id'],
                                              key))
            return True

    active_games[key] = {}
    active_games[key].update(NEW_GAME_TEMPLATE)
    active_games[key].update(game_data)
    active_games[key]['version'] = version
    active_games[key]['main_tracker'] = 1

    logger.debug('Added new game ID {0} hosted by {1} to '
                 'active_games: \n{2}'.format(active_games[key]['game_id'],
                                              key,
                                              active_games[key]))


def web_interface_ping(data, address):
    logger.debug('entered web_interface_ping')

    unpack_string = '=B4s'
    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed, dropping')
        return
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    if unpacked_data[1].decode() == 'ping':
        logger.debug('Ping received, sending pong')
        buf = struct.pack('4sI', 'pong'.encode(), last_list_response_time)
        dxx_sendto(buf, address, listen_socket)


def stale_game(key):
    logger.debug('entered stale_game')

    # Make sure we actually have a game active from this ip:port
    if not active_game_check(key):
        return False

    # archive games that are confirmed, have detailed stats, have a player1
    # whose name is greater than 1, and has been started, and has been up for
    # at least 5 minutes
    if (active_games[key]['confirmed'] and
            active_games[key]['detailed'] and
            active_games[key]['player1name'] and
            active_games[key]['start_time'] and
            (time.time() - active_games[key]['start_time']) / 60 >= 5):

        active_games[key]['archive_time'] = time.time()

        # create a dictionary to hold this game
        stale_game = {key: active_games[key]}

        filename = 'tracker/archive_data/game-{0}-{1}-{2}'.format(
            my_time(active_games[key]['start_time']),
            active_games[key]['player0name'],
            active_games[key]['mission_name'])

        if my_write_file(json.dumps(stale_game), filename):
            logger.info('Archived game ID {0} '
                        'hosted by {1}'.format(active_games[key]['game_id'],
                                               key))
    else:
        logger.info('Deleting game ID {0} hosted by {1}'.format(
            active_games[key]['game_id'], key))

    # Clean up the relay sockets
    if active_games[key]['relay_sock_id'] in udp_relay_sockets:
        relay_sock_id = active_games[key]['relay_sock_id']

        # First, remove any client sockets associated with this main relay
        # socket id
        for i in udp_relay_sockets[relay_sock_id]['clients']:
            client_sock_id = udp_relay_sockets[relay_sock_id]['clients'][i]
            logger.debug('Deleting client socket {0} from relay socket '
                         '{1}'.format(client_sock_id, udp_relay_sockets[relay_sock_id]))
            del udp_relay_sockets[client_sock_id]

        # Remove the main relay socket now
        logger.debug('Deleting main socket {0} from relay socket '
                     'list'.format(relay_sock_id,
                                   udp_relay_sockets[relay_sock_id]))
        del udp_relay_sockets[relay_sock_id]
        udp_relay_ports.append(relay_sock_id[1])
    else:
        logger.debug('Replay sock ID {0} not found in '
                     'udp_reply_sockets'.format(
            active_games[key]['relay_sock_id']))

        logger.debug('Relay sockets still active: \n{0}'.format(
            udp_relay_sockets))

    # Remove the game from the active games dict
    del active_games[key]


def setup_udp_relay(key):
    logger.debug('entered setup_udp_relay')

    # Open a socket for this game, but only do so if we have available ports
    # to handle this game
    if len(udp_relay_ports) > 0:
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.bind(('', udp_relay_ports[0]))
        except socket.error:
            logger.exception('Unable to bind socket, cannot setup relay for '
                             'game ID {0} hosted '
                             'by {1}'.format(active_games[key]['game_id'],
                                             key))
            return False

        sock_id = temp_socket.getsockname()

        # Note this sock_id so we can clean up this relay socket once the game goes stale
        active_games[key]['relay_sock_id'] = sock_id

        udp_relay_sockets[sock_id] = {}
        udp_relay_sockets[sock_id]['clients'] = {}
        udp_relay_sockets[sock_id]['game_id'] = key
        udp_relay_sockets[sock_id]['relay_addr'] = (active_games[key]['ip'],
                                                    active_games[key]['port'])
        udp_relay_sockets[sock_id]['relay_socket'] = None
        udp_relay_sockets[sock_id]['socket'] = temp_socket

        request_data = {'tracker_ver': TRACKER_PROTOCOL_VERSION,
                        'version': active_games[key]['version'],
                        'port': udp_relay_ports[0],
                        'game_id': active_games[key]['game_id'],
                        'release_major': active_games[key]['release_major'],
                        'release_minor': active_games[key]['release_minor'],
                        'release_micro': active_games[key]['release_micro']}

        dxx_send_register(request_data,
                          (main_tracker_address, main_tracker_port),
                          udp_relay_sockets[sock_id]['socket'])

        udp_relay_ports.pop(0)
    else:
        logger.error('No ports available to setup UDP relay for game ID {0} '
                     'hosted by {1}'.format(active_games[key]['game_id'], key))
        return False


def process_udp_relay(data, address, socket_):
    logger.debug('entered process_udp_relay')

    sock_id = socket_.getsockname()

    if sock_id not in udp_relay_sockets:
        logger.debug('Socket ID {0} no longer in the '
                     'socket list'.format(sock_id))
        return False

    if udp_relay_sockets[sock_id]['relay_socket'] == None:
        logger.debug('Sock ID {0} is a main game host socket'.format(sock_id))

        # If the address we got this incoming packet from was the main tracker
        # IP and port send it to the game host
        if (address == (main_tracker_address, main_tracker_port)):
            logger.debug('This appears to be an incoming tracker request')
            relay_addr = udp_relay_sockets[sock_id]['relay_addr']
            relay_socket = udp_relay_sockets[sock_id]['socket']
            udp_relay_sockets[sock_id]['pending_reqs'] = 1

        # Else, if, we got this incoming packet from the game host itself, AND,
        # we have a pending request from the tracker, relay this data to the
        # tracker
        elif (address == udp_relay_sockets[sock_id]['relay_addr'] and udp_relay_sockets[sock_id]['pending_reqs'] == 1):
            logger.debug('This appears to be a tracker response')
            relay_addr = (main_tracker_address, main_tracker_port)
            relay_socket = udp_relay_sockets[sock_id]['socket']
            udp_relay_sockets[sock_id]['pending_reqs'] = 0

        # Else, if, we got this incoming packet from a client that is already
        # know for this game host, go ahead and relay this packet to the game
        # host through the socket that was opened specifically for this client
        elif address in udp_relay_sockets[sock_id]['clients']:
            logger.debug('This appears to be a client we already know about')
            relay_addr = udp_relay_sockets[sock_id]['relay_addr']

            # Retrieve the socket id from this client from the clients dict
            # embedded in the dict for this main game host socket
            client_sock_id = udp_relay_sockets[sock_id]['clients'][address]

            # Relay through the socket for this specific client
            relay_socket = udp_relay_sockets[client_sock_id]['socket']

        # Else, if, we got this incoming packet from a client that we do not
        # already know about, go ahead and create a socket for it and relay
        # the data from this client to the game host, using this new socket
        elif address not in udp_relay_sockets[sock_id]['clients']:
            logger.debug('This appears to be a new client')
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # TODO: add error handling here
            client_socket.bind(('', 0))
            client_sock_id = client_socket.getsockname()

            # Update the main game host's client table with this address and
            # socket pair so we can find it when this client sends another
            # packeto the game host
            udp_relay_sockets[sock_id]['clients'][address] = client_sock_id
            logger.debug('Main game host socket entry updated with new client '
                         '{0}: \n{1}'.format(address,
                                             udp_relay_sockets[sock_id]))

            # Create a new entry for this client.
            #
            # relay_addr = the IP address of this client
            # relay_socket = the main game host socket
            # socket = the socket opened specific for this client
            udp_relay_sockets[client_sock_id] = {}
            udp_relay_sockets[client_sock_id]['relay_addr'] = address
            udp_relay_sockets[client_sock_id]['relay_socket'] = sock_id
            udp_relay_sockets[client_sock_id]['socket'] = client_socket

            logger.debug('New client socket entry created: \n{0}'.format(
                udp_relay_sockets[client_sock_id]))

            # Relay this client's traffic over to the game host
            relay_addr = udp_relay_sockets[sock_id]['relay_addr']

            # Relay through the socket for this specific client
            relay_socket = udp_relay_sockets[client_sock_id]['socket']

            logger.debug('relay addr - {0}'.format(relay_addr))
            logger.debug('relay socket - {0}'.format(relay_socket))
        else:
            logger.exception('I should never get here, if I do, '
                             'something is wrong')
            return False

    # Else, the socket we recieved this packet on has a relay_socket set which
    # means this socket was created for client and the relay socket is the one
    # the client is using to communicate with the game host, so, send the
    # data to the relay address and relay socket specified by this socket id.
    else:
        # As a security check, we should make sure the IP address we're getting
        # the data from is the same IP address this client is relay data to.
        relay_addr = udp_relay_sockets[sock_id]['relay_addr']
        relay_socket_id = udp_relay_sockets[sock_id]['relay_socket']
        relay_socket = udp_relay_sockets[relay_socket_id]['socket']

        if udp_relay_sockets[relay_socket_id]['relay_addr'] != address:
            logger.exception('This packet game in from someone other than '
                             'the original relay target, dropping')
            return False

    logger.debug('relay addr - {0}'.format(relay_addr))
    logger.debug('relay socket - {0}'.format(relay_socket))


    # Now, actually relay the data, which would be a pretty good idea
    if dxx_sendto(data, relay_addr, relay_socket):
        logger.debug('Relayed packet from '
                     '{0} to {1}'.format(address, relay_addr))
        return True
    else:
        return False


### Main Body ###
logger = logging.getLogger('dxx_logger')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s.%(msecs)d: %(module)s:'
                              '%(funcName)s:%(levelname)s: %(message)s',
                              datefmt='%m/%d/%Y %H:%M:%S')

# console logger
ch = logging.StreamHandler()
ch.setFormatter(formatter)
#ch.setLevel('INFO')

# rotating file logger
rfh = logging.handlers.RotatingFileHandler('tracker.log', maxBytes=1048576,
                                           backupCount=5)
rfh.setFormatter(formatter)

logger.addHandler(rfh)
#logger.addHandler(ch)

# handle command line arguments
parser = argparse.ArgumentParser(description='Python-based DXX Tracker',
                                 prog='tracker')
parser.add_argument('-i', '--int_ip', dest='int_ip', type=str,
                    nargs='+', help='IP address(es) of internal host(s).')
parser.add_argument('-q', '--query_main', action='store_true',
                    help='Query the main tracker for it\'s list of games.')
args = parser.parse_args()

int_ip_list = []
if isinstance(args.int_ip, list):
    for s in args.int_ip:
        try:
            socket.inet_aton(s)
            int_ip_list.append(s)
            logger.info('Added {0} to the internal IP address '
                        'list.'.format(s))
        except socket.error:
            logger.error('\'{0}\' is not a valid IP address and will be '
                         'ignored'.format(s))

# Determine what we should be doing as far as querying the main tracker
# for it's list of games
if args.query_main:
    try:
        main_tracker_address = socket.\
            gethostbyname('dxxtracker.reenigne.net')
        main_tracker_port = 42420
        logger.debug('Main tracker address - {0}:{1}'.format(
            main_tracker_address, main_tracker_port))
    except socket.error:
        logger.exception('Unable to determine main tracker IP address, '
                         'tracker will not be queried.')
        main_tracker_address = False
else:
    logger.info('Main Tracker will not be queried.')
    main_tracker_address = False

# constants
MAX_PLAYERS = 8
CALLSIGN_LENGTH = 8
NETGAME_NAME_LENGTH = 15
MISSION_NAME_LENGTH = 25
MAJOR_VERSION = 0
MINOR_VERSION = 58
MICRO_VERSION = 1
TRACKER_PROTOCOL_VERSION = 0
GAME_VARIANTS = ('rebirth 0.58.1', 'retro 1.3')
NEW_GAME_TEMPLATE = {'confirmed': 0, 'pending_info_reqs': 0, 'start_time': 0,
                     'detailed': 0, 'netgame_proto': 0, 'main_tracker': 0,
                     'relay_sock_id': None}
NON_RETRO_GAME_TEMPLATE = {'retro_proto': 0, 'alt_colors': 0,
                           'primary_dupe': 0, 'secondary_dupe': 0,
                           'secondary_cap': 0, 'born_burner': 0}

OPCODE_REGISTER = 0
OPCODE_UNREGISTER_OR_VERSION_DENY = 1
OPCODE_GAME_LIST_REQUEST = 2
OPCODE_GAME_INFO_RESPONSE = 3
OPCODE_GAME_INFO_LITE_RESPONSE = 5
OPCODE_GAME_LIST_RESPONSE = 22
OPCODE_WEBUI_IPC = 99

udp_relay_ports = [50000, 50001, 50002, 50003, 50004]
udp_relay_sockets = {}

# open a socket that will be used to communicate with DXX clients
listen_ip_address = '0.0.0.0'
# TODO: fix the port
listen_port = 17210
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listen_socket.bind((listen_ip_address, listen_port))

# open sockets used to query the existing tracker
d1x_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
d2x_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# create directories for output
for s in ['tracker', 'tracker/archive_data']:
    my_mkdir(s)

active_games = {}
stale_games = []
last_list_request_time = 0
last_list_response_time = 0
last_game_poll_time = 0

# set the external IP address
external_ip = get_external_ip()
last_external_ip_time = time.time()

logger.info('Tracker initialized')

# try to load old, existing game data, in case we crash and reboot
old_game_data = my_load_file('gamelist.txt')
if old_game_data:
    active_games.update(old_game_data)
    logger.debug('Loaded old game data: \n{0}'.format(active_games))

### debugging
#active_games['127.0.0.1:42424'] = {'alt_colors': 1, 'player2connected': 0, 'team1_name': '', 'port': 42424, 'player7deaths': 0, 'spawn_style': 3, 'player0kills': 0, 'max_time': 600, 'player5deaths': 0, 'player0name': 'arch', 'max_players': 8, 'status': 1, 'player3kills': 0, 'difficulty': 4, 'player4connected': 0, 'player7name': '', 'player1kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'player7kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'player5time': 0, 'player4kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'player5kills': 0, 'packet_loss_prevention': 1, 'start_time': 1407465207.975702, 'player0kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'pending_info_reqs': 1, 'flags': 4, 'secondary_dupe': 0, 'player1name': 'foobar', 'monitor_vector': 0, 'main_tracker': 0, 'team0_kills': 0, 'level_num': 1, 'retro_proto': 1, 'player7time': 0, 'mission_title': 'The Manes', 'player1time': 0, 'player4time': 0, 'player5name': '', 'segments_checksum': 35373, 'show_enemy_names': 1, 'allow_marker_view': 0, 'player0suicides': 0, 'secondary_cap': 0, 'short_packets': 4, 'player3deaths': 0, 'level_time': 0, 'player1connected': 0, 'player2name': '', 'respawn_concs': 0, 'mission_name': 'manes', 'player0deaths': 0, 'team0_name': '', 'release_major': 0, 'packets_sec': 30, 'players': 1, 'reactor_life': 300, 'player7kills': 0, 'player1deaths': 0, 'player5suicides': 0, 'player2time': 0, 'fair_colors': 0, 'player2deaths': 0, 'detailed': 1, 'release_minor': 58, 'mode': 0, 'player3kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'team1_kills': 0, 'player7connected': 0, 'player0time': 1408465213.008564, 'always_lighting': 0, 'player2kills': 0, 'ip': '127.0.0.1', 'player3connected': 0, 'player2kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'player1kills': 0, 'player4name': '', 'player5kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'release_micro': 1, 'bright_ships': 1, 'player4deaths': 0, 'game_id': 22094, 'player3suicides': 0, 'netgame_name': 'testing', 'confirmed': 1, 'player6deaths': 0, 'player6connected': 0, 'player0connected': 1, 'player4kills': 0, 'kill_goal': 20, 'primary_dupe': 0, 'player4suicides': 0, 'player5connected': 0, 'player1suicides': 0, 'player6kill_table': [0, 0, 0, 0, 0, 0, 0, 0], 'player6suicides': 0, 'refuse_players': 0, 'player6kills': 0, 'variant': 'retro 1.3', 'netgame_proto': 2130, 'player2suicides': 0, 'num_players': 1, 'allowed_items': 8191, 'team_vector': 0, 'player3name': '', 'player7suicides': 0, 'player6time': 0, 'version': 1, 'allow_colored_lights': 0, 'no_friendly_fire': 1, 'player3time': 0, 'tracker_ver': 0, 'player6name': ''}

while True:
    socket_list = [listen_socket, d1x_socket, d2x_socket]

    for i in udp_relay_sockets:
        socket_list.append(udp_relay_sockets[i]['socket'])

    readable, writeable, exception = select.select(socket_list, [], [], 1)

    if readable:
        for i in readable:

            # if this is on one of the relay sockets, handle accordingly
            if i.getsockname() in udp_relay_sockets:
                data, address = i.recvfrom(1024)
                process_udp_relay(data, address, i)
                continue

            data, address = i.recvfrom(1024)
            logger.info('Incoming packet from {0}:{1}, '
                        'data length: {2}'.format(address[0], address[1],
                        len(data)))
            logger.debug('Raw data received: {0}'.format(data))

            if data:
                if data[0] == OPCODE_REGISTER:
                    logger.debug('OPcode: register')
                    register_request(data, address)
                elif data[0] == OPCODE_UNREGISTER_OR_VERSION_DENY:
                    if len(data) == 5:
                        logger.debug('OPcode: unregister')
                        unregister_request(data, address)
                    elif len(data) == 9:
                        logger.debug('OPcode: version deny')
                        version_deny(address)
                    else:
                        logger.debug('OPcode: unknown, not unregister '
                                     'or version deny')
                elif data[0] == OPCODE_GAME_LIST_REQUEST:
                    logger.debug('OPcode: gamelist request')
                    game_list_request(data, address)
                elif (data[0] == OPCODE_GAME_INFO_RESPONSE or
                        data[0] == OPCODE_GAME_INFO_LITE_RESPONSE):
                    logger.debug('OPcode: info_response')
                    game_info_response(data, address)
                elif data[0] == OPCODE_GAME_LIST_RESPONSE:
                    # Make sure this game from the tracker and no some bad
                    # dude trying to do some malicious
                    if address[0] != main_tracker_address:
                        logger.error('Received game list response from '
                                     'someone other than the tracker')
                        continue

                    # check what socket we get this game_list_resp on,
                    # use that to populate the version field
                    if i == d1x_socket:
                        logger.debug('OPcode: game_list_response, '
                                     'received on d1x socket')
                        game_list_response(data, 1)
                    elif i == d2x_socket:
                        logger.debug('OPcode: game_list_response, '
                                     'received on d2x socket')
                        game_list_response(data, 2)
                    else:
                        logger.debug('OPcode: game_list_response, '
                                     'unknown socket')
                elif data[0] == OPCODE_WEBUI_IPC:
                        logger.debug('OPcode: web interface ping')
                        web_interface_ping(data, address)
                else:
                    logger.debug('OPcode: unknown - '.format(data[0]))

    for i in stale_games:
        logger.debug('Handling stale game_id: {0}'.format(i))
        stale_game(i)
    stale_games = []

    # Query the main tracker for games, if appropriate.
    if (main_tracker_address and
            (last_list_request_time == 0 or
            (time.time() - last_list_request_time >= 10))):
        logger.debug('Retrieving new game list from main tracker')
        last_list_request_time = time.time()

        dxx_send_game_list_request(1,
                                   (main_tracker_address, main_tracker_port),
                                   d1x_socket)
        time.sleep(0.025)
        dxx_send_game_list_request(2,
                                   (main_tracker_address, main_tracker_port),
                                   d2x_socket)

    # if it has been 5 seconds, poll the active games for stats
    if last_game_poll_time == 0 or (time.time() - last_game_poll_time >= 5):
        last_game_poll_time = time.time()

        # for each active game, send an info request
        for i in active_games:
            logger.debug('Polling game ID {0} hosted by '
                         '{1} for stats'.format(active_games[i]['game_id'], i))

            # send info_lite_req to unconfirmed games,
            # send full info_req to confirmed games
            if active_games[i]['confirmed'] == 0:
                game_info_request(0, i)
            else:
                game_info_request(1, i)

            # flag games that are not responding to info requests
            if active_games[i]['pending_info_reqs'] > 5:
                logger.debug('Game ID {0} hosted by {1} is stale'.format(
                    active_games[i]['game_id'], i))
                if i not in stale_games:
                    stale_games.append(i)

        # Write out the active_games dict so the web interface can render it
        filename = 'gamelist.txt'
        if my_write_file(json.dumps(active_games), filename):
            logger.debug('Wrote out active_games: \n{0}'.format(active_games))
        else:
            logger.debug('Error writing out active games')

    # if it has been 5 minutes, re-check the external IP address
    if last_external_ip_time == 0 or (time.time() - last_external_ip_time >= 300):
        external_ip = get_external_ip()
