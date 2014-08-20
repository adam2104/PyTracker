__author__ = 'Adam Gensler'


import logging
import os
import socket
import struct

logger = logging.getLogger('dxx_logger.dxxtoolkit')

# constants
MAJOR_VERSION = 0
MINOR_VERSION = 58
MICRO_VERSION = 1
OPCODE_REGISTER = 0
OPCODE_UNREGISTER_OR_VERSION_DENY = 1
OPCODE_GAME_LIST_REQUEST = 2
OPCODE_GAME_INFO_RESPONSE = 3
OPCODE_GAME_INFO_LITE_RESPONSE = 5
OPCODE_GAME_LIST_RESPONSE = 22

def dxx_sendto(buf, address, socket_):
    logger.debug('entered dxx_sendto')

    try:
        socket_.sendto(buf, address)
        return True
    except socket.error:
        logger.exception('Error occurred while sending the packet to '
                         '{0}:{1}'.format(address[0], address[1]))
        return False


def dxx_unpack(unpack_string, data):
    logger.debug('entered dxx_unpack')
    try:
        return struct.unpack(unpack_string, data)
    except struct.error:
        logger.exception('Data unpack failed')
        return False


def dxx_process_register(data):
    logger.debug('entered dxx_process_register')

    if len(data) == 15:
        unpack_string = '=BBBHIHHH'
    elif len(data) == 14:
        unpack_string = '=BBBHIHHB'
    else:
        logger.error('Received register with incorrect length')
        return False

    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed')
        return False
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    game_data = {}
    game_data['tracker_ver'] = unpacked_data[1]
    game_data['version'] = unpacked_data[2]
    game_data['port'] = unpacked_data[3]
    game_data['game_id'] = unpacked_data[4]
    game_data['release_major'] = unpacked_data[5]
    game_data['release_minor'] = unpacked_data[6]
    game_data['release_micro'] = unpacked_data[7]

    return game_data


def dxx_process_unregister(data):
    logger.debug('entered dxx_process_unregister')

    if len(data) == 5:
        unpack_string = '=BI'
    else:
        logger.error('Received unregister with incorrect length')
        return False

    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed')
        return False
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    game_data = {}
    game_data['game_id'] = unpacked_data[1]

    return game_data


def dxx_process_game_info_response(data):
    logger.debug('entered dxx_process_game_info_response')

    if len(data) == 73:
        # game_info_lite response
        unpack_string = '=BHHHI16s26s9sIBBBBBBB'
    elif len(data) == 510:
        # dxx rebirth 0.58.1 game_info
        unpack_string = ('=BHHH9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9s'
                         'BBB9sBBB9sBBB9sBBB16s26s9sIBBBBBBBBBIHHHHH18sII'
                         'IIIIIIhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh'
                         'hhhhhhhhhhhhhhhhhhhhhhhHhhhhhhhhhhhhhhhhhhIIIII'
                         'IIIIIIIIBBBBBBBBHBBB')
    elif len(data) == 519:
        # d1x retro 1.3 game_info
        unpack_string = ('=BHHH9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9s'
                         'BBB9sBBB9sBBB9sBBB16s26s9sIBBBBBBBBBIHHHHH18sII'
                         'IIIIIIhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh'
                         'hhhhhhhhhhhhhhhhhhhhhhhHhhhhhhhhhhhhhhhhhhIIIII'
                         'IIIIIIIIBBBBBBBBHBBBBBBBBBBBB')
    elif len(data) == 520:
        # d2x retro 1.3 game_info
        unpack_string = ('=BHHH9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9sBBB9s'
                         'BBB9sBBB9sBBB9sBBB16s26s9sIBBBBBBBBBIHHHHH18sII'
                         'IIIIIIhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh'
                         'hhhhhhhhhhhhhhhhhhhhhhhHhhhhhhhhhhhhhhhhhhIIIII'
                         'IIIIIIIIBBBBBBBBHBBBBBBBBBBBBB')
    else:
        logger.error('Received game info response with incorrect length')
        return False

    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed')
        return False
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    game_data = {}
    game_data['release_major'] = unpacked_data[1]
    game_data['release_minor'] = unpacked_data[2]
    game_data['release_micro'] = unpacked_data[3]

    if len(data) == 73:
        # game_info_lite response from DXX Rebirth and Retro
        game_data['game_id'] = unpacked_data[4]
        game_data['netgame_name'] = unpacked_data[5].decode().\
            replace('\x00', '')
        game_data['mission_title'] = unpacked_data[6].decode().\
            replace('\x00', '')
        game_data['mission_name'] = unpacked_data[7].decode().\
            replace('\x00', '')
        game_data['level_num'] = unpacked_data[8]
        game_data['mode'] = unpacked_data[9]
        game_data['refuse_players'] = unpacked_data[10]
        game_data['difficulty'] = unpacked_data[11]
        game_data['status'] = unpacked_data[12]
        game_data['players'] = unpacked_data[13]
        game_data['max_players'] = unpacked_data[14]
        game_data['flags'] = unpacked_data[15]
    else:
        # Full game_info response from DXX Rebirth and Retro
        game_data['netgame_name'] = unpacked_data[52].decode().\
            replace('\x00', '')
        game_data['mission_title'] = unpacked_data[53].decode().\
            replace('\x00', '')
        game_data['mission_name'] = unpacked_data[54].decode().\
            replace('\x00', '')
        game_data['level_num'] = unpacked_data[55]
        game_data['mode'] = unpacked_data[56]
        game_data['refuse_players'] = unpacked_data[57]
        game_data['difficulty'] = unpacked_data[58]
        game_data['status'] = unpacked_data[59]

        # num of players ever to connect to this game
        game_data['num_players'] = unpacked_data[60]

        game_data['max_players'] = unpacked_data[61]

        # num of currently connected players
        game_data['players'] = unpacked_data[62]

        game_data['flags'] = unpacked_data[63]
        game_data['team_vector'] = unpacked_data[64]
        game_data['allowed_items'] = unpacked_data[65]
        game_data['allow_marker_view'] = unpacked_data[66] # not used in D1
        game_data['always_lighting'] = unpacked_data[67] # not used in D1
        game_data['show_enemy_names'] = unpacked_data[68]
        game_data['bright_ships'] = unpacked_data[69]
        game_data['spawn_style'] = unpacked_data[70]
        game_data['team0_name'] = unpacked_data[71][0:8].decode().\
            replace('\x00', '')
        game_data['team1_name'] = unpacked_data[71][9:18].decode().\
            replace('\x00', '')
        game_data['segments_checksum'] = unpacked_data[144]
        game_data['team0_kills'] = unpacked_data[145]
        game_data['team1_kills'] = unpacked_data[146]
        game_data['kill_goal'] = unpacked_data[163] * 10
        game_data['max_time'] = unpacked_data[164] * 5 * 60
        game_data['level_time'] = unpacked_data[165]
        game_data['reactor_life'] = int(unpacked_data[166] / 65535)
        game_data['monitor_vector'] = unpacked_data[167]
        game_data['packets_sec'] = unpacked_data[184]
        game_data['short_packets'] = unpacked_data[185]
        game_data['packet_loss_prevention'] = unpacked_data[186]
        game_data['no_friendly_fire'] = unpacked_data[187]

        # retro options, decode as necessary
        if len(data) == 519 or len(data) == 520:
            game_data['retro_proto'] = unpacked_data[188]
            game_data['respawn_concs'] = unpacked_data[189]
            game_data['allow_colored_lights'] = unpacked_data[190]
            game_data['fair_colors'] = unpacked_data[191]
            game_data['alt_colors'] = unpacked_data[192]
            game_data['spawn_style'] = unpacked_data[193]
            game_data['primary_dupe'] = unpacked_data[194]
            game_data['secondary_dupe'] = unpacked_data[195]
            game_data['secondary_cap'] = unpacked_data[196]

        # if this is D2 retro, we need to handle 1 extra byte of data
        if len(data) == 520:
            game_data['born_burner'] = unpacked_data[197]

        # get the player data out
        player_step = 0
        suicides_step = 80
        deaths_step = 147
        kills_step = 155
        kill_table_step = 80
        for num in range(4, 36, 4):
            plr_num = 'player{0}'.format(player_step)
            game_data[plr_num + 'name'] = \
                (unpacked_data[num].decode().split('\x00', 1))[0]
            game_data[plr_num + 'connected'] = unpacked_data[num + 1]
            game_data[plr_num + 'deaths'] = unpacked_data[deaths_step]
            game_data[plr_num + 'kills'] = unpacked_data[kills_step]
            game_data[plr_num + 'suicides'] = unpacked_data[suicides_step]

            # pull out the kill table data, 8x8 matrix, player0 - 7
            game_data[plr_num + 'kill_table'] = []
            for i in range(kill_table_step, kill_table_step + 8):
                game_data[plr_num + 'kill_table'].append(unpacked_data[i])
            kill_table_step += 8

            player_step += 1
            deaths_step += 1
            kills_step += 1
            suicides_step += 9

    return game_data


def dxx_process_game_list_request(data):
    logger.debug('entered dxx_process_game_list_request')

    if len(data) == 3:
        unpack_string = '=BH'
    else:
        logger.error('Received game_list_req with incorrect length')
        return False

    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed')
        return False
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    game_data = {}
    game_data['version'] = unpacked_data[1]

    return game_data


def dxx_process_game_list_response(data):
    logger.debug('entered dxx_process_game_list_response')

    if len(data) < 85 or len(data) > 93:
        logger.error('Received game_list_resp with incorrect length')
        return False

    # the IP address in this response is a variable length field.
    # find the first null character after skipping the first
    # two bytes (opcode, ipv6 flag), this signifies the end of the ip address,
    # use that value to build the unpacking string
    ip_addr_len = str((data.find(b'\x00', 2)) - 1)

    unpack_string = '=BB{0}sHHHHI16s26s9sIBBBBBBBB'.format(ip_addr_len)
    logger.debug('Unpack_string: {0}'.format(unpack_string))

    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed')
        return False
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    game_data = {}
    game_data['ipv6'] = unpacked_data[1]
    game_data['ip'] = unpacked_data[2].decode().replace('\x00', '')
    game_data['port'] = unpacked_data[3]
    game_data['release_major'] = unpacked_data[4]
    game_data['release_minor'] = unpacked_data[5]
    game_data['release_micro'] = unpacked_data[6]
    game_data['game_id'] = unpacked_data[7]
    game_data['netgame_name'] = unpacked_data[8].decode().replace('\x00', '')
    game_data['mission_title'] = unpacked_data[9].decode().replace('\x00', '')
    game_data['mission_name'] = unpacked_data[10].decode().replace('\x00', '')
    game_data['level_num'] = unpacked_data[11]
    game_data['mode'] = unpacked_data[12]
    game_data['refuse_players'] = unpacked_data[13]
    game_data['difficulty'] = unpacked_data[14]
    game_data['status'] = unpacked_data[15]
    game_data['players'] = unpacked_data[16]
    game_data['max_players'] = unpacked_data[17]
    game_data['flags'] = unpacked_data[18]

    return game_data


def dxx_process_version_deny(data):
    logger.debug('entered dxx_process_version_deny')

    if len(data) == 9:
        unpack_string = '=BHHHH'
    else:
        logger.error('Received version deny with incorrect length')
        return False

    unpacked_data = dxx_unpack(unpack_string, data)
    if not unpacked_data:
        logger.error('Data unpack failed')
        return False
    else:
        logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

    game_data = {}
    game_data['release_major'] = unpacked_data[1]
    game_data['release_minor'] = unpacked_data[2]
    game_data['release_micro'] = unpacked_data[3]
    game_data['netgame_proto'] = unpacked_data[4]

    return game_data


def dxx_send_register_response(address, socket_):
    logger.debug('entered dxx_send_register_response')

    buf = struct.pack('=B', 21)

    if dxx_sendto(buf, address, socket_):
        logger.debug('Sent register response to {0}:{1}'.format(
            address[0], address[1]))
        return True
    else:
        return False


def dxx_send_game_info_request(version, req_type, netgame_proto_version,
                               address, socket_):
    logger.debug('entered dxx_send_game_info_request')

    request_id = 'D{0}XR'.format(version).encode()

    # send either a lite_req and a full req depending on the type
    if req_type == 0:
        buf = struct.pack('=B4sHHH', 4, request_id, MAJOR_VERSION,
                          MINOR_VERSION, MICRO_VERSION)
    elif req_type == 1:
        buf = struct.pack('=B4sHHHH', 2, request_id, MAJOR_VERSION,
                          MINOR_VERSION, MICRO_VERSION, netgame_proto_version)
    else:
        logger.error('Unknown request type')
        return False

    if dxx_sendto(buf, address, socket_):
        logger.debug('Sent game info request to {0}:{1}'.format(address[0],
                                                                address[1]))
        return True
    else:
        return False


def dxx_send_game_list_request(version, address, socket_):
    logger.debug('entered dxx_send_game_list_req')

    buf = struct.pack('=BBB', 2, version, 0)
    if dxx_sendto(buf, address, socket_):
        logger.debug('Sent game list request to {0}:{1}'.format(
            address[0], address[1]))
        return True
    else:
        return False


def dxx_send_game_list_response(data, address, socket_):
    '''
    :param data: dict containing the fields returned in game_info_lite_reply
    :param address: tuple ('ip_address', port)
    :param socket_: socket to send response out on
    :return: True is data was sent successful, False otherwise
    '''

    logger.debug('entered dxx_send_game_list_response')

    opcode = 22
    ipv6_flag = 0

    # Reply length is variable depending on the length of the IP address so
    # calculate the IP address length to build the correct packing string
    pack_string = '=BB{0}sHHHHI16s26s9sIBBBBBBBB'.format(
        len(data['ip']) + 1)
    logger.debug('Packing string: {0}'.format(pack_string))

    buf = struct.pack(pack_string,
                      opcode,
                      ipv6_flag,
                      data['ip'].encode(),
                      data['port'],
                      data['release_major'],
                      data['release_minor'],
                      data['release_micro'],
                      data['game_id'],
                      data['netgame_name'].encode(),
                      data['mission_title'].encode(),
                      data['mission_name'].encode(),
                      data['level_num'],
                      data['mode'],
                      data['refuse_players'],
                      data['difficulty'],
                      data['status'],
                      data['players'],
                      data['max_players'],
                      data['flags'],
                      0)

    if dxx_sendto(buf, address, socket_):
        logger.debug('Sent game list response to {0}:{1}'.format(
            address[0], address[1]))
        return True
    else:
        return False


def dxx_send_register(data, address, socket_):
    logger.debug('entered dxx_send_register')

    pack_string = '=BBBHIHHH'

    buf = struct.pack(pack_string,
                      OPCODE_REGISTER,
                      data['tracker_ver'],
                      data['version'],
                      data['port'],
                      data['game_id'],
                      data['release_major'],
                      data['release_minor'],
                      data['release_micro'])

    if dxx_sendto(buf, address, socket_):
        logger.debug('Sent game register request to {0}:{1}'.format(
            address[0], address[1]))
        return True
    else:
        return False


def dxx_send_unregister(data, address, socket_):
    logger.debug('entered dxx_send_unregister')

    pack_string = '=BI'

    buf = struct.pack(pack_string,
                      OPCODE_UNREGISTER_OR_VERSION_DENY,
                      data['game_id'])

    if dxx_sendto(buf, address, socket_):
        logger.debug('Sent game unregister request to {0}:{1}'.format(
            address[0], address[1]))
        return True
    else:
        return False
