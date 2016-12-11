"""
    Configuration values and constants for the instant messaging system.
"""

# class ServerConfiguration():
#     Address = ('127.0.0.1', 8082)
#     Resources = Enum('ServerResources', 'LIST CRL')
#     Methods = Enum('ServerMethods', 'AUTHENTICATE RESOURCE LOGOUT')
#     Public_Key = get_public_key('server_public_key') # TODO: generate this when the server starts up and then put it in a file or something?
#
# class Constants():
#     GREETING = 'IWANTTOTALK'
#     IFS = b'<break>'

from enum import Enum

from common.crypto import get_public_key


__all__ = ['CLIENT_STATE', 'SERVER_ADDRESS', 'SERVER_METHODS', 'SERVER_RESOURCES', 'SERVER_PUBKEY', 'MESSAGE_STATUSES', 'GREETING', 'FAREWELL', 'IFS', 'INITIAL_USER_ACCOUNTS']

CLIENT_STATE = Enum('ClientState', 'INITIAL UNATHENTICATED AUTHENTICATED SHUTDOWN')

SERVER_ADDRESS = ('127.0.0.1', 8082)
SERVER_METHODS = Enum('ServerMethods', 'AUTHENTICATE RESOURCE LOGOUT')
SERVER_RESOURCES = Enum('ServerResources', 'LIST CRL')
SERVER_PUBKEY = get_public_key('resources/server_public_key')

MESSAGE_STATUSES = Enum('MessageStatuses', 'OK ERROR')
GREETING = 'IWANTTOTALK'
FAREWELL = 'LOGOUT'
IFS = b'<break>'

INITIAL_USER_ACCOUNTS = [
    ['Alice', 'Al1ceisC**l%13'],
    ['Bob', 'D0ntmessw/Tex4s~88'],
    ['test', 'password'],
    ['foo', 'password'],
    ['bar', 'password']
]
