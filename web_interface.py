__author__ = 'agensler'

from dxxtoolkit import dxx_sendto, dxx_unpack
from my_functions import *
import logging
import logging.handlers
import os
import re
import select
import socket
import struct
import time


def ping_tracker(address):
    logger.debug('entered ping_tracker')

    global last_alt_tracker_ping
    global last_list_response_time

    web_interface_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_list = [web_interface_socket]
    buf = struct.pack('=B4s', 99, 'ping'.encode())
    dxx_sendto(buf, address, web_interface_socket)

    readable, writeable, exception = select.select(socket_list, [], [], 1)
    if readable:
        for i in readable:
            data, address = i.recvfrom(512)

            unpack_string = '=4sI'
            unpacked_data = dxx_unpack(unpack_string, data)
            if not unpacked_data:
                logger.error('Data unpack failed')
                return
            else:
                logger.debug('Unpacked data: \n{0}'.format(unpacked_data))

            if unpacked_data[0].decode() == 'pong':
                last_alt_tracker_ping = time.time()
                last_list_response_time = unpacked_data[1]
                web_interface_socket.close()
                return True
    else:
        web_interface_socket.close()
        return False


def set_color(player_num, alt_colors):
    logger.debug('entered set_color')
    if player_num == 0:
        return '#7878B8'
    elif player_num == 1:
        return '#D80000'
    elif player_num == 2:
        return '#00B800'
    elif player_num == 3:
        return '#F058F8'
    elif player_num == 4:
        return '#F88000'
    elif player_num == 5:
        if alt_colors == 0:
            return '#C08830'
        else:
            return '#7828C8'
    elif player_num == 6:
        if alt_colors == 0:
            return '#70A860'
        else:
            return 'black'
    elif player_num == 7:
        return '#E8E800'
    else:
        return 'black'


def build_html_header(mode):
    html_output = '<html><head>'

    if mode == 'tracker':
        html_output += '<meta http-equiv="refresh" content="60">'

    html_output += '<title>DXX Retro Tracker</title>' \
                   '<STYLE TYPE="text/css">' \
                   '<!--TD{font-family: Arial;}--->' \
                   '</STYLE></head>' \
                   '<body bgcolor=#D0D0D0>' \
                   '<table style=width:100% align=center>' \
                   '<tr>' \
                   '<td style=width:10% align=left></td>' \
                   '<td style=width:80% align=center bgcolor=#FFFFFF>' \
                   '<table style=width:95% bgcolor=#FFFFFF>' \
                   '<tr>' \
                   '<td align=center><br>DXX Retro Tracker</td>' \
                   '</tr>' \
                   '<tr>' \
                   '<td><hr></td>' \
                   '</tr>'

    # start the row for the games table
    html_output += '<tr><td>'

    return html_output


def build_html_basic_stats(data):
    logger.debug('entered build_html_basic_stats')

    html_output = '<table style=width:100% align=center cellspacing=0 ' \
                  'border=1>'

    # game header
    if 'variant' in data:
        variant = 'DXX {0}'.format(data['variant'].upper())
    else:
        variant = 'DXX UNKNOWN'

    if data['main_tracker'] == 1:
        tracker = '<a href=\'http://dxxtracker.reenigne.net\'>' \
                  'Main Tracker' \
                  '</a>'
    else:
        tracker = '<a href=\'http://retro-tracker.game-server.cc\'>' \
                  'Alternate Tracker' \
                  '</a>'

    if data['start_time'] > 0:
        html_output += '<tr><td colspan=5 bgcolor=#D0D0D0 ><b>{0} - </b>' \
                       'Start time: {1} GMT - ' \
                       'Hosted on {2}' \
                       '</td></tr>'.format(variant,
                                           my_time(data['start_time']),
                                           tracker)
    else:
        html_output += '<tr>' \
                       '<td colspan=5 bgcolor=#D0D0D0>' \
                       '<b>{0} - </b>Hosted on {1}</td></tr>'.format(variant,
                                                                  tracker)

    # start row
    html_output += '<tr>'

    # start column
    html_output += '<td>'

    # first column
    html_output += '<b>Game Name: </b>{0}'.format(data['netgame_name'])
    html_output += '<br><b>Mission: </b>{0}'.format(data['mission_title'])
    html_output += '<br><b>Level Number: </b>{0}'.format(data['level_num'])
    html_output += '<br><b>Players: </b>{0}/{1}'.format(data['players'],
                                                        data['max_players'])

    # game mode
    var = ''
    if data['mode'] == 0:
        var = 'Anarchy'
    elif data['mode'] == 1:
        var = 'Team Anarchy'
    elif data['mode'] == 2:
        var = 'Robot Anarchy'
    elif data['mode'] == 3:
        var = 'Cooperative'
    elif data['mode'] == 4:
        var = 'Capture the Flag'
    elif data['mode'] == 5:
        var = 'Hoard'
    elif data['mode'] == 6:
        var = 'Team Hoard'
    elif data['mode'] == 7:
        var = 'Bounty'
    else:
        var = 'Unknown'
    html_output += '<br><b>Mode: </b>{0}'.format(var)

    # end column
    html_output += '</td>'

    # start column
    html_output += '<td>'

    # second column

    # status
    var = ''
    if data['status'] == 0:
        var = 'Menu'
    elif data['status'] == 1:
        var = 'Playing'
    elif data['status'] == 2:
        var = 'Browsing'
    elif data['status'] == 3:
        var = 'Waiting'
    elif data['status'] == 4:
        var = 'Starting'
    elif data['status'] == 5:
        var = 'End Level'
    else:
        var = 'Unknown'
    html_output += '<b>Status: </b>{0}'.format(var)

    # joinable
    var = ''
    if data['status'] == 4:
        var = 'Open'
    elif (data['flags'] & 1) == 0 \
            and data['refuse_players'] == 0:
        var = 'Open'
    elif (data['flags'] & 1) == 1:
        var = 'Closed'
    elif data['refuse_players'] == 1:
        var = 'Restricted'
    else:
        var = 'Unknown'
    html_output += '<br><b>Joinable: </b>{0}'.format(var)

    if (data['flags'] & 4) == 4:
        html_output += '<br><b>Show on MiniMap: </b>Y'
    else:
        html_output += '<br><b>Show on MiniMap: </b>N'

    # difficulty
    var = ''
    if data['difficulty'] == 0:
        var = 'Trainee'
    elif data['difficulty'] == 1:
        var = 'Rookie'
    elif data['difficulty'] == 2:
        var = 'Hotshot'
    elif data['difficulty'] == 3:
        var = 'Ace'
    elif data['difficulty'] == 4:
        var = 'Insane'
    else:
        var = 'Unknown'
    html_output += '<br><b>Difficulty: </b>{0}'.format(var)

    # version
    var = ''
    if data['version'] == 1:
        var = 'D1 {0}.{1}.{2}'.format(str(data['release_major']),
                                      str(data['release_minor']),
                                      str(data['release_micro']))
    elif data['version'] == 2:
        var = 'D2 {0}.{1}.{2}'.format(str(data['release_major']),
                                      str(data['release_minor']),
                                      str(data['release_micro']))
    else:
        var = 'Unknown'
    html_output += '<br><b>Version: </b>{0}'.format(var)

    # end column
    html_output += '</td>'

    # if we aren't doing detailed output, finish things out
    #data['detailed'] = 0
    if data['detailed'] == 0:
        html_output += '<td style=width:25%>Detailed info not available</td>'
        html_output += '<td style=width:25%>Detailed info not available</td>'

    return html_output


def build_html_detailed_stats(data, mode):
    logger.debug('entered build_html_detailed_stats')

    # start column
    html_output = '<td>'

    # third column

    # reactor life
    var = ''
    if data['reactor_life'] > 0:
        var = '{0} min(s)'.format(int(data['reactor_life'] / 60))
    else:
        var = 'n/a'
    html_output += '<b>Reactor Life: </b>{0}'.format(var)

    # max time
    var = ''
    if data['max_time'] > 0:
        var = '{0} min(s)'.format(int(data['max_time'] / 60))
    else:
        var = 'n/a'
    html_output += '<br><b>Max Time: </b>{0}'.format(var)

    # time elapsed
    var = ''
    if data['start_time'] == 0:
        var = 'n/a'
        time_elapsed = 0
    else:
        time_elapsed = int((time.time() - data['start_time']) / 60)
        var = '{0} min(s)'.format(time_elapsed)
    html_output += '<br><b>Time Elapsed: </b>{0}'.format(var)

    # compute estimated time remaining in game
    var = ''
    if data['max_time'] > 0:
        var = '{0} min(s)'.format(int((data['max_time'] / 60) - time_elapsed))
    else:
        var = 'n/a'
    html_output += '<br><b>Time Left: </b>{0}'.format(var)

    # kill goal
    var = ''
    if data['kill_goal'] > 0:
        var = data['kill_goal']
    else:
        var = 'n/a'
    html_output += '<br><b>Kill Goal: </b>{0}'.format(var)

    # end column
    html_output += '</td>'

    # start column
    html_output += '<td valign="top">'

    # fourth column

    # spawn style
    var = ''
    if data['spawn_style'] == 0:
        var = 'No Invuln'
    elif data['spawn_style'] == 1:
        var = 'Short Invuln'
    elif data['spawn_style'] == 2:
        var = 'Long Invuln'
    elif data['spawn_style'] == 3:
        var = 'Preview'
    else:
        var = 'Unknown'
    html_output += '<b>Respawn Style: </b>{0}'.format(var)

    # short packets
    if data['short_packets'] == 1:
        html_output += '<br><b>Short packets: </b> Y'
    else:
        html_output += '<br><b>Short packets: </b> N'

    # packets per second
    if data['packets_sec'] > 0:
        var = '{0}pps'.format(data['packets_sec'])
    else:
        var = 'Unknown'
    html_output += '<br><b>Packets/sec: </b>{0}'.format(var)

    # bright ships
    if data['bright_ships'] == 1:
        html_output += '<br><b>Bright Ships: </b> Y'
    else:
        html_output += '<br><b>Bright Ships: </b> N'

    # end column
    html_output += '</td>'

    # start column
    html_output += '<td valign="top">'

    # fifth column

    # display retro specific stuff only if its a retro game
    if data['variant'] == GAME_VARIANTS[1]:

        # retro proto
        if data['retro_proto'] > 0:
            html_output += '<b>P2P (Retro) Proto: </b> Y'
        else:
            html_output += '<b>P2P (Retro) Proto: </b> N'

        # if D2, highlight burner option
        if data['version'] == 2:
            if data['born_burner'] == 1:
                html_output += '<br><b>Spawn with burner: </b> Y'
            else:
                html_output += '<br><b>Spawn with burner: </b> N'

        # primaries dupe factor
        var = ''
        if data['primary_dupe'] > 0:
            var = '{0}x'.format(str(data['primary_dupe']))
        else:
            var = 'n/a'
        html_output += '<br><b>Primary Dupe: </b>{0}'.format(var)

        # secondaries dupe factor
        var = ''
        if data['secondary_dupe'] > 0:
            var = '{0}x'.format(str(data['secondary_dupe']))
        else:
            var = 'n/a'
        html_output += '<br><b>Secondary Dupe: </b>{0}'.format(var)

        # secondaries cap factor
        var = ''
        if data['secondary_cap'] == 0:
            var = 'Uncapped'
        elif data['secondary_cap'] == 1:
            var = 'Max 6'
        elif data['secondary_cap'] == 2:
            var = 'Max 2'
        else:
            var = 'Unknown'
        html_output += '<br><b>Secondary Cap: </b>{0}'.format(var)
    else:
        html_output += 'Not a DXX Retro game.<br>Detailed info is not ' \
                       'available.'

    # end column
    html_output += '</td>'

    # end row
    html_output += '</tr>'

    # allowed items
    if (data['allowed_items'] != 8191 and data['allowed_items'] != 134217727):
        # blank line
        html_output += '<tr><td colspan=5 bgcolor=#D0D0D0><b>Disallowed ' \
                       'Items</b></td></tr>'

        html_output += '<tr>' \
                       '<td colspan=5>' \
                       '<table style=width:100% align=center cellspacing=0>'

        # find out which items are enabled / disabled
        # if this is d1, only do the first 13 items, if d2, do them all
        if data['version'] == 1:
            item_limit = 13
        else:
            item_limit = len(ITEM_LIST)

        for x in range(0, item_limit):
            if (data['allowed_items'] & 2**x) == 0:
                html_output += '<tr><td>{0}</td></tr>'.format(ITEM_LIST[x])

        html_output += '</table></td>'

        # end row
        html_output += '</tr>'

    # print the team score board if this is a team game
    if data['team_vector'] > 0:
        # blank line
        html_output += '<tr><td colspan=5 bgcolor=#D0D0D0><b>Team Score ' \
                       'Board</b></td></tr>'

        # start row
        html_output += '<tr>'

        # start player table
        html_output += '<td colspan=5>' \
                       '<table style=width:100% cellspacing=0>' \
                       '<tr>' \
                       '<td style=width:25%>Team</td>' \
                       '<td style=width:25%>Kills</td>' \
                       '<td style=width:25%></td>' \
                       '<td style=width:25%></td></tr>'

        # display the teams in sorted order
        if data['team0_kills'] >= data['team1_kills']:
            team_order = [0, 1]
        else:
            team_order = [1, 0]

        for x in team_order:
            text_color = set_color(x, data['alt_colors'])
            html_output += '<tr style="color:{0};"><td>{1}</td>' \
                           '<td>{2}</td></tr>'.\
                format(text_color,
                       data['team' + str(x) + '_name'],
                       data['team' + str(x) + '_kills'])

        # close out player table
        html_output += '</table></td>'

        # end row
        html_output += '</tr>'

    # blank line
    html_output += '<tr><td colspan=5 bgcolor=#D0D0D0><b>Score ' \
                   'Board</b></td></tr>'

    # start row
    html_output += '<tr>'

    # start player table
    html_output += '<td colspan=5>' \
                   '<table style=width:100% cellspacing=0>' \
                   '<tr>' \
                   '<td>Player</td>' \
                   '<td>Kills</td>' \
                   '<td>Deaths</td>' \
                   '<td>Suicides</td>' \
                   '<td>Kill/Death Ratio</td>' \
                   '<td>Time in Game</td>'

    # end row
    html_output += '</tr>'

    # build a sorted list of players based on number of kills so we can
    # display the scoreboard in that order
    sorted_players = {}
    for x in range(0, 8):
        player = 'player{0}'.format(str(x))
        sorted_players[x] = data[player + 'kills']
    sorted_players = sorted(sorted_players,
                            key=sorted_players.get,
                            reverse=True)

    total_players = 0
    for x in range(0, 8):
        player = 'player{0}'.format(str(sorted_players[x]))
        name = data[player + 'name']
        if len(name) > 0:
            total_players += 1

            # if this is a team game, set the text_color
            if data['team_vector'] > 0:
                team_num = (data['team_vector'] & 2**sorted_players[x]) \
                           >> sorted_players[x]
                text_color = set_color(team_num, data['alt_colors'])
            else:
                text_color = set_color(sorted_players[x], data['alt_colors'])

            # start row
            html_output += '<tr style="color:{0};">'.format(text_color)

            if mode == 'tracker' and data[player + 'connected'] == 0:
                html_output += '<td>' + name + '(disconnected)</td>'
            else:
                html_output += '<td>' + name + '</td>'

            html_output += '<td>{0}</td>'.format(
                str(data[player + 'kills']))
            html_output += '<td>{0}</td>'.format(
                str(data[player + 'deaths']))
            html_output += '<td>{0}</td>'.format(
                str(data[player + 'suicides']))

            # calculate kill/death ratio
            if data[player + 'kills'] > 0 and data[player + 'deaths'] > 0:
                kill_death = data[player + 'kills'] / data[player + 'deaths']
            elif data[player + 'kills'] > 0 and data[player + 'deaths'] == 0:
                kill_death = data[player + 'kills']
            else:
                kill_death = 0
            html_output += '<td>{0:.2f}</td>'.format(kill_death)

            # calculate time in game
            if data[player + 'time'] > 0:
                if mode == 'tracker':
                    html_output += '<td>{0} min(s)</td>'.\
                        format(int(
                        (time.time() - data[player + 'time']) / 60))
                else:
                    html_output += '<td>{0} min(s)</td>'.\
                        format(int(
                        (data['archive_time'] - data[player + 'time']) / 60))

            else:
                html_output += '<td>n/a</td>'

            html_output += '</tr>'

    # close out player table
    html_output += '</table></td>'

    # end row
    html_output += '</tr>'

    # blank line
    html_output += '<tr><td colspan=5 bgcolor=#D0D0D0><b>Detailed Score ' \
                   'Board</b></td></tr>'

    # start row
    html_output += '<tr>'

    # start player table
    html_output += '<td colspan=5>' \
                   '<table style=width:100% cellspacing=0>' \
                   '<tr><td style=width:10%>&nbsp;</td>'

    # print kill table header
    for x in range(0, 8):
        player = 'player{0}'.format(str(x))
        name = data[player + 'name']
        if len(name) > 0:
            # if this is a team game, set the text_color
            if data['team_vector'] > 0:
                team_num = (data['team_vector'] & 2**x) >> x
                text_color = set_color(team_num, data['alt_colors'])
            else:
                text_color = set_color(x, data['alt_colors'])

            html_output += '<td style="width:10%; color:{0};">{1}' \
                           '</td>'.format(text_color, name)
        else:
            html_output += '<td style=width:10%>&nbsp;</td>'

    # end row
    html_output += '</tr>'

    # print kill table
    for x in range(0, total_players):
        # print the player name
        player = 'player{0}'.format(str(x))
        name = data[player + 'name']

        # if this is a team game, set the text_color
        if data['team_vector'] > 0:
            team_num = (data['team_vector'] & 2**x) >> x
            text_color = set_color(team_num, data['alt_colors'])
        else:
            text_color = set_color(x, data['alt_colors'])

        html_output += '<tr style="color:{0};">'.format(text_color)
        html_output += '<td>' + name + '</td>'

        # print the kills for that player
        for i in range(0, total_players):
            html_output += '<td>{0}</td>'.format(
                data[player + 'kill_table'][i])

        # end row
        html_output += '</tr>'

    # close out player table
    html_output += '</table></td>'

    return html_output


def build_html_footer(mode):
    html_output = '</td></tr>' \
                  '<tr><td><hr></td></tr>' \
                  '<tr><td><font size=2>Data above from the main and ' \
                  'alternate trackers. For the main tracker, go ' \
                  '<a href=\'http://dxxtracker.reenigne.net/\'>here</a>.' \
                  '<br>To use the alternate tracker, configure \'<b>' \
                  '<i>-tracker_hostaddr retro-tracker.game-server.cc</b>' \
                  '</i>\' in d1x.ini or d2x.ini, or add it to your D1X or ' \
                  'D2X shortcut.<br>Games monitored by this tracker are ' \
                  'archived ' \
                  '<a href="./archive/">here</a>.' \
                  '<br>Created by: ' \
                  '<a href="mailto:arch@a.gnslr.us">Arch</a>' \
                  '</td></tr>'

    # query the tracker status so we can update the page
    if mode == 'tracker':
        if ping_tracker(('127.0.0.1', 42420)):
            html_output += '<tr>' \
                           '<td bgcolor=#00FF00>Alternate Tracker is UP' \
                           '</td>' \
                           '</tr>'

            # try to guess whether or not the main tracker is up
            if last_list_response_time == 0:
                html_output += '<tr>' \
                               '<td bgcolor=#FFFF00>Last message from Main' \
                               ' Tracker: unknown' \
                               '</td>' \
                               '</tr>'
            elif int((time.time() - last_list_response_time) / 3600) < 12:
                html_output += '<tr>' \
                               '<td bgcolor=#00FF00>Last message from Main' \
                               ' Tracker: {0} GMT' \
                               '</td>' \
                               '</tr>'.format(my_time(last_list_response_time))
            elif int((time.time() - last_list_response_time) / 3600) > 12 and \
                    int((time.time() - last_list_response_time) / 3600) < 25:
                html_output += '<tr><td bgcolor=#FFFF00>Last message from Main' \
                               ' Tracker: {0} GMT</td></tr>'.format(
                    my_time(last_list_response_time))
            else:
                html_output += '<tr><td bgcolor=#FF0000>Last message from Main' \
                               ' Tracker: {0} GMT</td></tr>'.format(
                    my_time(last_list_response_time))
        else:
            logger.error('Alternate tracker is down!')
            if last_alt_tracker_ping == 0:
                html_output += '<tr>' \
                               '<td bgcolor=#FF0000>Alternate Tracker is ' \
                               'DOWN.' \
                               '</td>' \
                               '</tr>'
            else:
                html_output += '<tr>' \
                               '<td bgcolor=#FF0000>Alternate Tracker is ' \
                               'DOWN.' \
                               ' Last successful ping: {0} GMT' \
                               '</td></tr>'.format(my_time(last_alt_tracker_ping))

        html_output += '<tr>' \
               '<td>Last page refresh: {0} GMT' \
               '</td></tr>'.format(my_time(time.time()))

    html_output += '</font></table><br></td><td style=width:10% align=right></td></tr></table></body></html>'

    return html_output


### Main Body ###

logger = logging.getLogger('dxx_logger')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s.%(msecs)d: %(module)s:'
                              '%(funcName)s:%(levelname)s: %(message)s',
                              datefmt='%m/%d/%Y %H:%M:%S')

ch = logging.StreamHandler()
ch.setFormatter(formatter)
#ch.setLevel('INFO')

rfh = logging.handlers.RotatingFileHandler('web_interface.log',
                                           maxBytes=1048576,
                                           backupCount=5)
rfh.setFormatter(formatter)

logger.addHandler(rfh)
logger.addHandler(ch)

ITEM_LIST = ('Laser Upgrade', 'Quad Lasers', 'Vulcan Cannon', 'Vulcan Ammo',
             'Spreadfire Cannon', 'Plasma Cannon', 'Fusion Cannon',
             'Homing Missiles', 'Proximity Bombs', 'Smart Missiles',
             'Mega Missiles', 'Cloaking', 'Invulnerability', 'Super Lasers',
             'Gauss Cannon', 'Helix Cannon', 'Phoenix Cannon', 'Omega Cannon',
             'Flash Missiles', 'Guided Missiles', 'Smart Mines',
             'Mercury Missiles', 'Earthshaker Missiles', 'Afterburners',
             'Ammo Rack', 'Energy Converter', 'Headlight')
GAME_VARIANTS = ('rebirth 0.58.1', 'retro 1.3')


for i in ['tracker', 'tracker/archive', 'tracker/archive_data',
          'tracker/archive_data/old']:
    my_mkdir(i)

last_alt_tracker_ping = 0
last_list_response_time = 0
archived_count = 0

while True:
    html_output = build_html_header('tracker')
    game_data = my_load_file('gamelist.txt')

    if game_data:
        for i in game_data:
            #logger.debug('Active game data: \n{0}'.format(game_data[i]))
            if game_data[i]['confirmed']:
                html_output += build_html_basic_stats(game_data[i])

                if game_data[i]['detailed']:
                    html_output += build_html_detailed_stats(game_data[i], 'tracker')

                # close out this game's table
                html_output += '</tr></table><br>'

    html_output += build_html_footer('tracker')
    my_write_file(html_output, 'tracker/index.html')

    # Parse through any games that get saved into the archive_data directory
    archive_list = os.listdir('tracker/archive_data/')
    for f in archive_list:
        if re.match(r'^game-', f):
            filename = 'tracker/archive_data/{0}'.format(f)
            game_data = my_load_file(filename)

            if game_data:
                for i in game_data:
                    logger.debug('Archive game data: '
                                 '\n{0}'.format(game_data[i]))
                    if game_data[i]['confirmed']:
                        html_output = build_html_header('archive')
                        html_output += build_html_basic_stats(game_data[i])

                        if game_data[i]['detailed']:
                            html_output += build_html_detailed_stats(
                                game_data[i], 'archive')

                        # close out this game's table
                        html_output += '</tr></table><br>'
                        html_output += build_html_footer('archive')

                        if my_write_file(html_output,
                                         'tracker/archive/{0}.html'.format(f)):
                            logger.debug('Wrote out archived game '
                                         '{0}'.format(filename))
                        else:
                            logger.debug('Error writing out '
                                         'archived game {0}'.format(filename))
            os.rename(filename, 'tracker/archive_data/old/{0}'.format(f))

    # Get the list of files in the archive directory. If there's more than
    # last time, generate a fresh index.html for that directory so people
    # don't have to scroll down to the bottom.
    archived_games = sorted(os.listdir('tracker/archive/'), reverse=True)

    if (len(archived_games) != archived_count):
        logger.debug('Generating updated archive index')

        archive_index = '<html><head><title>DXX Tracker Archive</title>' \
                        '</head><body>'

        for i in archived_games:
            if re.match(r'^game-', i):
                archive_index += '<a href="./{0}">{0}</a><br>'.format(i)

        archive_index += '</body></html>'

        filename = 'tracker/archive/index.html'
        if my_write_file(archive_index, filename):
            logger.debug('Wrote out archive index')
        else:
            logger.debug('Error writing out archive index')

        archived_count = len(archived_games)

    time.sleep(5)