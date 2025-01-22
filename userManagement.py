import sqlite3 as sql

from src import password_hashing as ps
from src import sanitize_and_validate as sv


def insertUser(username, password):
    if userExists(username):
        return False

    password = ps.hashPassword(password)

    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?,?)", (username, password)
    )
    con.commit()
    con.close()


def userExists(username: str) -> bool:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    exists = cur.fetchone() is not None
    con.close()
    return exists
