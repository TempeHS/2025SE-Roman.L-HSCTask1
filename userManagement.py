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
    cur.execute("INSERT INTO users (email, password, firstName, lastName) VALUES (?,?,?,?)", (email, password, firstname, lastname))
    con.commit()
    con.close()
    return True


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
    cur.execute("SELECT id, email, password FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    con.close()
    return user if user else False


def getUserById(user_id):
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    con.close()
    return user

## Devlog related functions
def map_devlog_rows(data):
    return [{
        'title': row[2],
        'body': sv.convertLinks(row[3]),
        'date': row[4],
        'fullname': row[5]
    } for row in data]

def insertDevlog(title: str, body: str, fullname: str, email: str, date: str) -> None:
    safe_title = sv.sanitize(title)
    safe_body = sv.sanitize(body)
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO developer_log (title, body, email, date, fullname) VALUES (?, ?, ?, ?, ?)",(safe_title, safe_body, email, date, fullname))
    con.commit()
    con.close()

def listDevlogs() -> list:
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM developer_log").fetchall()
    con.close()
    return map_devlog_rows(data)

## Devlog query functions
def searchByDeveloper(query):
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE fullname LIKE ?", (f'%{query}%',))
    data = cur.fetchall()
    con.close()
    return map_devlog_rows(data)

def searchByDate(query):
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE date LIKE ?", (f'%{query}%',))
    data = cur.fetchall()
    con.close()
    return map_devlog_rows(data)

def searchByContent(query):
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE title LIKE ? OR body LIKE ?", (f'%{query}%', f'%{query}%'))
    data = cur.fetchall()
    con.close()
    return map_devlog_rows(data)

def searchAll(query):
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE title LIKE ? OR body LIKE ? OR fullname LIKE ? OR date LIKE ?", (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
    data = cur.fetchall()
    con.close()
    return map_devlog_rows(data)
