__author__ = 'Adam Gensler'

import json
import logging
import os
import socket
import time

logger = logging.getLogger('dxx_logger.my_functions')


def my_mkdir(dir_):
    logger.debug('entered my_mkdir')
    try:
        os.mkdir(dir_)
        logger.debug('directory created: {0}'.format(dir_))
    except OSError as e:
        if e.errno == 17:
            logger.debug('directory already exists: {0}'.format(dir_))
            pass


def my_write_file(data, filename):
    logger.debug('entered my_write_file')

    try:
        game_data_file = open(filename, 'w')
        game_data_file.write(data)
        game_data_file.flush()
        game_data_file.close()
        return True
    except OSError:
        logger.exception('Error writing data to file')
        return False

def my_time(data):
    logger.debug('entered my_time')
    formatted_time = time.strftime("%m-%d-%Y-%H-%M-%S", time.gmtime(data))
    return formatted_time


def my_load_file(filename):
    logger.debug('entered my_load_file')

    try:
        data_file = open(filename, 'r')
    except IOError:
        logger.exception('Unable to open data file')
        return False

    try:
        data = json.loads(data_file.read())
    except ValueError:
        logger.exception('Error decoding data file')
        data_file.close()
        return False

    return data


def my_gethostbyname(hostname):
    logger.debug('entered my_gethostbyname')
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        logger.exception('Unable to resolve hostname')
        return False
