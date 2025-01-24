import sqlite3 as sql

from src import sanitize_and_validate as sv
from src import password_hashing as psh


## User related functions
def insertUser(username, password):
    if userExists(username):
        return False

    password = psh.hashPassword(password)

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


def retrieveUsers(username: str) -> tuple:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT id, username, password FROM users WHERE username = ?", (username,)
    )
    user = cur.fetchone()
    con.close()
    return user if user else False


## Devlog related functions
def insertDevlog(title: str, body: str, username: str, date: str) -> None:
    safe_title = sv.sanitize(title)
    safe_body = sv.sanitize(body)
    safe_username = sv.sanitize(username)
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("""
        INSERT INTO developer_log (title, body, username, date) 
        VALUES (?, ?, ?, ?)""",
        (safe_title, safe_body, safe_username, date)
    )
    con.commit()
    con.close()

def listDevlogs() -> list:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM developer_log").fetchall()
    con.close()
    dev_logs = [{
        'title': row[1],
        'body': row[2],
        'username': row[3],
        'date': row[4]
    } for row in data]
    return dev_logs
