import sqlite3 as sql

from src import sanitize_and_validate as sv
from src import password_hashing as psh


## User related functions
def insertUser(email, password, firstname, lastname):
    if userExists(email):
        return False

    password = psh.hashPassword(password)
    email = sv.sanitize(email)
    firstname = sv.sanitize(firstname)
    lastname = sv.sanitize(lastname)
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (email, password, firstName, lastName) VALUES (?,?,?,?)", (email, password, firstname, lastname)
    )
    con.commit()
    con.close()


def userExists(email: str) -> bool:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT email FROM users WHERE email = ?", (email,))
    exists = cur.fetchone() is not None
    con.close()
    return exists


def retrieveUsers(email: str) -> tuple:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT id, email, password FROM users WHERE email = ?", (email,)
    )
    user = cur.fetchone()
    con.close()
    return user if user else False


def getUserById(user_id):
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    )
    user = cur.fetchone()
    con.close()
    return user

## Devlog related functions
def insertDevlog(title: str, body: str, fullname: str, email: str, date: str) -> None:
    safe_title = sv.sanitize(title)
    safe_body = sv.sanitize(body)
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("""
        INSERT INTO developer_log (title, body, email, date, fullname) 
        VALUES (?, ?, ?, ?, ?)""",
        (safe_title, safe_body, email, date, fullname)
    )
    con.commit()
    con.close()

def listDevlogs() -> list:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM developer_log").fetchall()
    con.close()
    dev_logs = [{
        'title': row[2],
        'body': row[3],
        'fullname': row[5],
        'date': row[4]
    } for row in data]
    return dev_logs
