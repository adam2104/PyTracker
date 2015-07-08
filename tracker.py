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
        logger.warning('Game hosted by {0} not found in '
                     'active_games'.format(key))
        return False


def allocate_socket(address = '', port = 0):
    logger.debug('entered allocate_socket')

    socket_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_.bind((address, port))

    logger.debug('Allocated socket {0}'.format(socket_.getsockname()))

    return socket_


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
    active_games[key]['socket'] = allocate_socket()
    active_games[key]['register_ip'] = address[0]
    active_games[key]['register_port'] = address[1]

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
    # address the unregister came from and hope for the best.
    for i in active_games:
        if ((active_games[i]['game_id'] == game_data['game_id']) and
                (active_games[i]['ip'] == address[0])):
            logger.info('Unregistering game ID {0} hosted by {1}'.format(
                game_data['game_id'], i))

            # add this game to the stale_games list so we can handle it on the
            # next garbage collection loop
            stale_games.append(i)
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
                               address, active_games[key]['socket'])

    active_games[key]['pending_info_reqs'] += 1


def game_info_response(data, address):
    logger.debug('entered game_info_response')

    key = '{0}:{1}'.format(address[0], address[1])

    # Make sure we actually have a game active from this ip:port
    if not active_game_check(key):
        return False

    # Make sure we actually have a request pending before processing the data
    if active_games[key]['pending_info_reqs'] == 0:
        logger.error('Received info response from {0} when no info '
                     'response was pending'.format(key))
        return False
    else:
        active_games[key]['pending_info_reqs'] = 0

    game_data = dxx_process_game_info_response(data, active_games[key]['version'])
    if not game_data:
        logger.debug('Unable to handle game_info response')
        return False

    # if this is a game_info_lite_response, make sure the game ID in the
    # response matches the game ID we have stored for this game. If not, mark
    # the game stale and return
    if data[0] == OPCODE_GAME_INFO_LITE_RESPONSE:
        if game_data['game_id'] != active_games[key]['game_id']:
            logger.error('Received game_info_lite_response with a different '
                         'gameID than know gameID, marking existing game stale')
            stale_game(key)
            return False
        else:
            active_games[key].update(game_data)

    # Check whether or not this game has already been confirmed by an info_lite
    # response. If not, mark it as confirmed and then return, even if this is
    # a detailed response with data we could use. This will prevent game state
    # mismatches when Rebirth games are hosted, quit, and rehosted when info
    # requests are in-flight over the network. We'll get detailed info from
    # those games on the next pass around.
    if active_games[key]['confirmed'] == 0:
        active_games[key]['confirmed'] = 1

        if active_games[key]['main_tracker'] == 0:
            # This must be a game registered directly with us, and we've just
            # confirmed it, so, send the register ACK at this point
            register_address = (active_games[key]['register_ip'],
                                active_games[key]['register_port'])

            dxx_send_register_response(register_address, listen_socket)
            for i in range(1, 3):
                threading.Timer(i * 0.025, dxx_send_register_response,
                                [register_address, listen_socket]).start()

        logger.debug('Confirmed game ID {0} hosted by {1}'.format(
            active_games[key]['game_id'], key))

        return True

    # If the opcode for this game was 3, this is a full game info response
    if data[0] == OPCODE_GAME_INFO_RESPONSE:

        # full game_info_responses do not include the gameID field, so we need
        # to validate that this is the same game as the one we have stored. We
        # do this by comparing a few fields that cannot change once the game
        # has already started.

        if active_games[key]['detailed'] == 1:
            if (game_data['netgame_name'] != active_games[key]['netgame_name'] or
                    game_data['player0name'] != active_games[key]['player0name'] or
                    game_data['player0deaths'] < active_games[key]['player0deaths'] or
                    game_data['mission_name'] != active_games[key]['mission_name']):
                logger.error('Received game_info_response that appears to be for a '
                         'game different than the one already know for this '
                         'host, marking existing game stale.')
                stale_game(key)
                return False

        # if we've made it here, this game must be the same one as the one we're
        # tracking, so go ahead and update the active_games entry for it.
        active_games[key].update(game_data)

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

    # If we don't have a start time recorded for this game, and, if the game
    # has actually started playing, go ahead and record the (approx) start time
    if (active_games[key]['start_time'] == 0 and
            active_games[key]['status'] == 1):
        active_games[key]['start_time'] = time.time()

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

    # check the main game version, make sure we can support it
    if not check_version(game_data['release_major'],
                         game_data['release_minor'],
                         game_data['release_micro']):
        logger.error('Unknown game version, dropping')
        return False

    # check the netgame protocol version to make sure we know how to decode
    # the output. If not, set the version to unknown so we use just game info
    # lite requests.
    if game_data['netgame_proto'] in SUPPORTED_NETGAME_PROTO_VERSIONS:
        active_games[key]['netgame_proto'] = game_data['netgame_proto']
        logger.debug('Netgame protocol for game ID {0} host by {1} '
             'set to {2}'.format(active_games[key]['game_id'],
                                   key,
                                   active_games[key]['netgame_proto']))
    else:
        active_games[key]['netgame_proto'] = 'unknown'
        logger.debug('Unknown Netgame protocol for game ID {0} host by {1}'.
                     format(active_games[key]['game_id'], key))


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
                if s == ip_addr and external_ip:
                    logger.debug('Internal host, swapped IP {0} for '
                                 '{1}'.format(ip_addr, external_ip))
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

    # check the game version, make sure we can support it
    if not check_version(game_data['release_major'],
                         game_data['release_minor'],
                         game_data['release_micro']):
        logger.error('Received game list response with incorrect '
                     'game version, dropping')
        return False

    # make sure there's a valid IP or an actual port number here
    if (game_data['ip'] == '0.0.0.0' or game_data['port'] < 1024):
        logger.error('Invalid IP or port value under 1024, dropping')
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
    active_games[key]['socket'] = allocate_socket()

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

    # Because this is a stale game we're about to archive, or delete, mark
    # the socket stale and then remove it from the active_game entry to avoid
    # causing a json encode/decode error when the active game list is written
    # to a file
    stale_sockets.append(active_games[key]['socket'])
    del active_games[key]['socket']

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
            del active_games[key]
    else:
        logger.info('Deleting game ID {0} hosted by {1}'.format(
            active_games[key]['game_id'], key))
        del active_games[key]


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
logger.addHandler(ch)

# handle command line arguments
parser = argparse.ArgumentParser(description='Python-based DXX Tracker',
                                 prog='tracker')
parser.add_argument('--int_ip', dest='int_ip', nargs='+',
                    help='IP address(es) of internal host(s), requires '
                         '--hostname')
parser.add_argument('--ext_ip', dest='ext_ip', help='External IP / Hostname '
                                                    'for this tracker')
parser.add_argument('--peer_hostname', dest='peer_hostname',
                    help='IP / Hostname of peer tracker to query for '
                         'games list')
parser.add_argument('--peer_port', dest='peer_port',
                    help='Port of peer tracker to query for games list '
                         '(default: 42420)', default=42420)
args = parser.parse_args()

int_ip_list = []
if isinstance(args.int_ip, list):
    # Make sure the user also specified and external hostname to be swapped out
    # for the list of internal IP addresses specified
    if not args.ext_ip:
        parser.error('--ext_ip must also be specified when using --int_ip')
    else:
        external_ip = my_gethostbyname(args.ext_ip)
        if external_ip:
            logger.info('External IP {0} will be used when hosting internal '
                        'games to external players'.format(external_ip))
        else:
            logger.error('Unable to resolve hostname, will try again later')

    for s in args.int_ip:
        try:
            socket.inet_aton(s)
            int_ip_list.append(s)
            logger.info('Added {0} to the internal IP address '
                        'list.'.format(s))
        except socket.error:
            logger.error('\'{0}\' is not a valid IP address and will be '
                         'ignored'.format(s))

if args.peer_hostname:
    peer_address = my_gethostbyname(args.peer_hostname)
    if peer_address:
        peer_address = (peer_address, args.peer_port)
        logger.info('Peer tracker address at {0} will be queried for '
                    'games'.format(peer_address))
    else:
        logger.error('Unable to resolve hostname of peer tracker, will try '
                     'again later')
else:
    peer_address = False

# constants
MAX_PLAYERS = 8
CALLSIGN_LENGTH = 8
NETGAME_NAME_LENGTH = 15
MISSION_NAME_LENGTH = 25
MAJOR_VERSION = 0
MINOR_VERSION = 58
MICRO_VERSION = 1
SUPPORTED_NETGAME_PROTO_VERSIONS = (2130, 2131, 2943)
TRACKER_PROTOCOL_VERSION = 0

NEW_GAME_TEMPLATE = {'confirmed': 0, 'pending_info_reqs': 0, 'start_time': 0,
                     'detailed': 0, 'netgame_proto': 0, 'main_tracker': 0,
                     'tweet': 0}

OPCODE_REGISTER = 0
OPCODE_UNREGISTER_OR_VERSION_DENY = 1
OPCODE_GAME_LIST_REQUEST = 2
OPCODE_GAME_INFO_RESPONSE = 3
OPCODE_GAME_INFO_LITE_RESPONSE = 5
OPCODE_GAME_LIST_RESPONSE = 22
OPCODE_WEBUI_IPC = 99

# open a socket that will be used to communicate with DXX clients
listen_ip_address = '0.0.0.0'
listen_port = 42420
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
stale_sockets = []

last_list_request_time = 0
last_list_response_time = 0
last_game_poll_time = 0
last_address_lookup_time = time.time()

logger.info('Tracker initialized')

# try to load old, existing game data, in case we crash and reboot
old_game_data = my_load_file('gamelist.txt')
if old_game_data:
    active_games.update(old_game_data)
    logger.debug('Loaded old game data: \n{0}'.format(active_games))

    # Allocate sockets for the loaded games
    for i in active_games:
        active_games[i]['socket'] = allocate_socket()

while True:
    socket_list = [listen_socket, d1x_socket, d2x_socket]

    # Add any new game sockets to the socket_list so that we can handle
    # incoming packets from those games
    for i in active_games:
        if active_games[i]['socket'] not in socket_list:
            socket_list.append(active_games[i]['socket'])

    readable, writeable, exception = select.select(socket_list, [], [], 1)

    if readable:
        for i in readable:
            data, address = dxx_recvfrom(i)

            if data == False and address == False:
                logger.debug('Error reading data from socket {0}'.format(i))
                continue

            logger.info('Incoming packet from {0}:{1}, '
                        'data length: {2}'.format(address[0], address[1],
                        len(data)))

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
                    # dude trying to do something malicious
                    if address != peer_address:
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

    # close game sockets that have been marked stale
    for i in stale_sockets:
        logger.debug('Close stale socket {0}'.format(i))
        i.close()
    stale_sockets = []

    # Query the peer tracker for games, if appropriate.
    if (peer_address and
            (last_list_request_time == 0 or
            (time.time() - last_list_request_time >= 10))):
        logger.debug('Retrieving new game list from peer tracker '
                     '{0}'.format(peer_address))
        last_list_request_time = time.time()

        dxx_send_game_list_request(1, peer_address, d1x_socket)
        time.sleep(0.025)
        dxx_send_game_list_request(2, peer_address, d2x_socket)

    # if it has been 5 seconds, poll the active games for stats
    if last_game_poll_time == 0 or (time.time() - last_game_poll_time >= 5):
        last_game_poll_time = time.time()

        # for each active game, send an info request
        for i in active_games:
            logger.debug('Polling game ID {0} hosted by '
                         '{1} for stats'.format(active_games[i]['game_id'], i))

            # send info_lite_req to unconfirmed games or games with unknown
            # net protocol versions.
            # send full info_req to confirmed games
            if (active_games[i]['confirmed'] == 0 or
                active_games[i]['netgame_proto'] == 'unknown'):
                game_info_request(0, i)
            else:
                game_info_request(1, i)

            # If the game hasn't responded to an Info Request for 6 intervals,
            # close and reopen the per-game socket in an attempt to get data
            # from the game.
            if active_games[i]['pending_info_reqs'] == 6:
                logger.debug('Game ID {0} hosted by {1} is not responding, '
                             'closing and reopening game '
                             'socket'.format(active_games[i]['game_id'], i))

                # don't actually close the socket, mark it stale to
                # avoid causing a fderror in the select loop
                stale_sockets.append(active_games[i]['socket'])
                active_games[i]['socket'] = allocate_socket()

            # If the game hasn't responded in more than a minute, perhaps it
            # really is gone and we should mark it stale
            elif active_games[i]['pending_info_reqs'] > 12:
                logger.debug('Game ID {0} hosted by {1} is stale'.format(
                    active_games[i]['game_id'], i))
                if i not in stale_games:
                    stale_games.append(i)

        # Write out the active_games dict so the web interface can render it
        filename = 'gamelist.txt'
        games_to_write = {}

        # Only write out games that are confirmed
        for i in active_games:
            if active_games[i]['confirmed']:
                games_to_write[i] = {}
                games_to_write[i].update(active_games[i])

                # Drop the socket data so we can json dump this data later
                del games_to_write[i]['socket']

        if my_write_file(json.dumps(games_to_write), filename):
            logger.debug('Wrote out active_games: \n{0}'.format(active_games))
        else:
            logger.debug('Error writing out active games')

        # Re-query external IP addresses every 5 minutes in case it changes
        # since the last time we started
        if (time.time() - last_address_lookup_time >= 300):
            if args.ext_ip:
                external_ip = my_gethostbyname(args.ext_ip)
                if external_ip:
                    logger.info('External IP {0} will be used when hosting '
                                'internal games to external '
                                'players'.format(external_ip))
                else:
                    logger.error('Unable to resolve hostname, will '
                                 'try again later')

            if args.peer_hostname:
                peer_address = my_gethostbyname(args.peer_hostname)
                if peer_address:
                    peer_address = (peer_address, args.peer_port)
                    logger.info('Peer tracker address at {0} will be queried '
                                'for games'.format(peer_address))
                else:
                    logger.error('Unable to resolve hostname of peer tracker, '
                                 'will try again later')

            last_address_lookup_time = time.time()
