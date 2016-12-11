"""
    Methods for accessing and initializing the database of the instant
    messaging system.
"""

import sqlite3 as sqlite
from time import time

from common.config import INITIAL_USER_ACCOUNTS
from common.crypto import encode, hashn
from common.exceptions import *

__all__ = ['initialize_db', 'fetch_user_record', 'update_user_record']


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
    WHERE USERS.ID == ?
'''
)


### Methods ####################################################################
def initialize_db():
    with sqlite.connect('resources/users.db') as con:
        cur = con.cursor()
        cur.execute(SQL_BUILD_USER_TABLE)
        for username, password in INITIAL_USER_ACCOUNTS:
            cur.execute(SQL_CREATE_USER_RECORD, [
                username,
                hashn(encode(password), 1000),
                1000,
                None
            ])


def fetch_user_record(username):
    with sqlite.connect('resources/users.db') as con:
        cur = con.cursor()
        result_set = cur.execute(SQL_FETCH_USER_RECORD, [username])
        user = result_set.fetchone()
        if user is None or not result_set.fetchone() is None:
            raise UsernameVerificationError()
        user_id, _, passwd_hash, n, _ = user
        return user_id, passwd_hash, n


def update_user_record(uid, phash, n):
    with sqlite.connect('resources/users.db') as con:
        cur = con.cursor()
        cur.execute(SQL_UPDATE_USER_RECORD, [phash, n, int(time()), uid])
