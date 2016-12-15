"""
    Methods for accessing and initializing the database of the instant
    messaging system.
"""

import os
import time
import sqlite3 as sqlite

from common.exceptions import *
from common.crypto import encode, hashn


__all__ = ['initialize_db', 'fetch_user_record', 'update_user_record']


### Constants ##################################################################
INITIAL_USER_ACCOUNTS = [
    ['Alice', 'Whit3R@bbit'],
    ['Bob', 'joy0painting'],
    ['Trudy', 'valkyries48' ],
    ['test', '123'],
    ['foo', '123'],
    ['bar', '123']
]
DB_LOCATION = 'resources/server.db'


### SQL Statements #############################################################
SQL_BUILD_USER_TABLE = (
'''
    CREATE TABLE IF NOT EXISTS USERS (
        ID              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        NAME            TEXT UNIQUE NOT NULL,
        PASSWD_HASH     TEXT NOT NULL,
        N               INTEGER NOT NULL,
        LAST_LOGIN      INTEGER
    )
'''
)
SQL_CREATE_USER_RECORD = (
'''
    INSERT INTO USERS (
        NAME,
        PASSWD_HASH,
        N,
        LAST_LOGIN
    ) VALUES (?, ?, ?, ?)
'''
)
SQL_FETCH_USER_RECORD = (
'''
    SELECT ID,
           NAME,
           PASSWD_HASH,
           N,
           LAST_LOGIN
    FROM USERS WHERE NAME == ?
'''
)
SQL_UPDATE_USER_RECORD = (
'''
    UPDATE USERS SET
        PASSWD_HASH = ?,
        N = ?,
        LAST_LOGIN = ?
    WHERE USERS.NAME == ?
'''
)


### Methods ####################################################################
def initialize_db():
    """ Initializes the database for the server. """
    # remove db if it already exists
    if os.path.isfile(DB_LOCATION):
        os.remove(DB_LOCATION)
    # build db and populate users
    with sqlite.connect(DB_LOCATION) as con:
        try:
            cur = con.cursor()
            cur.execute(SQL_BUILD_USER_TABLE)
            for username, password in INITIAL_USER_ACCOUNTS:
                cur.execute(SQL_CREATE_USER_RECORD, [
                    username,
                    hashn(encode(password), 1000),
                    1000,
                    None
                ])
        except sqlite.Error:
            raise DatabaseError()


def fetch_user_record(username):
    """ Fetches and returns a user record for a given username. """
    with sqlite.connect(DB_LOCATION) as con:
        try:
            cur = con.cursor()
            result_set = cur.execute(SQL_FETCH_USER_RECORD, [ username ])
            user = result_set.fetchone()
            # ensure that one and only one result is returned
            if user is None or not result_set.fetchone() is None:
                raise UsernameVerificationError()
            # (user_id, username, password_hash, n, last_login)
            return user
        except sqlite.Error:
            raise DatabaseError()


def update_user_record(username, passwd_hash):
    """ Updates the user record of a given username, replacing the password
        hash and decrementing n. """
    with sqlite.connect(DB_LOCATION) as con:
        try:
            cur = con.cursor()
            *_, n, _  = fetch_user_record(username)
            cur.execute(SQL_UPDATE_USER_RECORD, [
                passwd_hash,
                n-1,
                int(time.time()),
                username
            ])
        except sqlite.Error:
            raise DatabaseError()
