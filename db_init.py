import sqlite3 as sqlite
from time import time

from common.crypto import hashn

SQL_CREATE_USER_RECORD = '''
    INSERT INTO USERS (
        NAME,
        PASSWD_HASH,
        N,
        LAST_LOGIN
    ) VALUES (?, ?, ?, ?)'''

USERS = [
    ['Alice', 'Al1ceisC**l%13'],
    ['Bob', 'D0ntmessw/Tex4s~88'],
    ['test', 'password'],
    ['foo', 'password'],
    ['bar', 'password']
]



with sqlite.connect('resources/users.db') as con:
    cur = con.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS USERS (
            ID              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            NAME            TEXT UNIQUE NOT NULL,
            PASSWD_HASH     TEXT NOT NULL,
            N               INTEGER NOT NULL,
            LAST_LOGIN      INTEGER
        )'''
    )

    try:
        for user in USERS:
            username, password = user
            n = 1000
            passwd_hash = hashn(password.encode('utf-8'), n)
            cur.execute(SQL_CREATE_USER_RECORD, [username, passwd_hash, n, None])
    except sqlite.Error as e:
        print(e)
