__author__ = 'Adam Gensler'

import json
import logging
import os
import socket
import time
import tweepy

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


def my_init_twitter():
    logger.debug('entered my_init_twitter')

    twitter_creds = my_load_file('twitter_creds')
    if twitter_creds:
        # check for required fields
        if (('consumer_key' not in twitter_creds) or
                ('consumer_secret' not in twitter_creds) or
                ('access_token' not in twitter_creds) or
                ('access_token_secret' not in twitter_creds)):
            logger.error('Credentials missing')
            twitter = False
        else:
            # init twitter connection
            auth = tweepy.OAuthHandler(twitter_creds['consumer_key'],
                                       twitter_creds['consumer_secret'])
            auth.secure = True
            auth.set_access_token(twitter_creds['access_token'],
                                  twitter_creds['access_token_secret'])
            twitter = tweepy.API(auth)
            logger.info('Successfully loaded twitter credentials file')
    else:
        logger.error('Unable to load twitter credentials file')
        twitter =  False

    return twitter


def my_twitter_update_status(api, tweet):
    logger.debug('entered my_twitter_update_status')

    # check to make sure the API passed in is actually a tweepy API
    if isinstance(api, tweepy.API):
        try:
            api.update_status(status=tweet)
            logger.debug('Successfully sent tweet')
            return True
        except tweepy.TweepError:
            logger.exception('Unable to send tweet')
            return False
    else:
        return False

def my_determine_joinable(flags, refuse_players):
    logger.debug('entered my_determine_joinable')

    if (flags & 1) == 0 and refuse_players == 0:
        return 'Open'
    elif (flags & 1) == 1:
        return 'Closed'
    elif refuse_players == 1:
        return 'Restricted'
    else:
        return 'Unknown'
