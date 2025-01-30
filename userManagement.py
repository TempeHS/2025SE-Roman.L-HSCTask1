import sqlite3 as sql

from flask_login import UserMixin
from src import sanitize_and_validate as sv, password_hashing as psh
import time
import random

class User(UserMixin):
    def __init__(self, id, email, firstname, lastname):
        self.id = id
        self.email = email
        self.firstname = firstname
        self.lastname = lastname

## User related functions
def insertUser(email, password, firstname, lastname):
    if userExists(email):
        return False

    password = psh.hashPassword(password)
    email = sv.sanitize(email).lower()
    firstname = sv.sanitize(firstname)
    lastname = sv.sanitize(lastname)

    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO users (email, password, firstname, lastname) VALUES (?,?,?,?)", (email, password, firstname, lastname))
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
    time.sleep(random.uniform(0.1, 0.2))
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT id, email, password, firstname, lastname FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    con.close()
    return user if user else False


def getUserById(user_id):
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    con.close()
    if user:
        return User(user[0], user[1], user[3], user[4])
    return user


def deleteUserById(user_id):
    try:
        con = sql.connect(".databaseFiles/database.db")
        cur = con.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        con.commit()
        con.close()
        return True
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False

## Devlog related functions
def mapDevlogRows(data):
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
    return mapDevlogRows(data)

## Devlog query functions
def searchByDeveloper(query):
    safe_query = sv.sanitizeQuery(query)
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE fullname LIKE ?", (f'%{safe_query}%',))
    data = cur.fetchall()
    con.close()
    return mapDevlogRows(data)

def searchByDate(query):
    safe_query = sv.sanitizeQuery(query)
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE date LIKE ?", (f'%{safe_query}%',))
    data = cur.fetchall()
    con.close()
    return mapDevlogRows(data)

def searchByContent(query):
    safe_query = sv.sanitizeQuery(query)
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE title LIKE ? OR body LIKE ?", (f'%{safe_query}%', f'%{safe_query}%'))
    data = cur.fetchall()
    con.close()
    return mapDevlogRows(data)

def searchAll(query):
    safe_query = sv.sanitizeQuery(query)
    con = sql.connect('.databaseFiles/database.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM developer_log WHERE title LIKE ? OR body LIKE ? OR fullname LIKE ? OR date LIKE ?", (f'%{safe_query}%', f'%{safe_query}%', f'%{safe_query}%', f'%{safe_query}%'))
    data = cur.fetchall()
    con.close()
    return mapDevlogRows(data)
