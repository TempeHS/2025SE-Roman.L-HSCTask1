import sqlite3 as sql

import html
import time
import random
from datetime import datetime, timedelta
from flask import flash, redirect, url_for
from flask_login import UserMixin
from src import sanitize_and_validate as sv, password_hashing as psh


class User(UserMixin):
    def __init__(self, user_id, email, firstname, lastname):
        self.id = user_id
        self.email = email
        self.firstname = firstname
        self.lastname = lastname

## User related functions
def insertUser(email, password, firstname, lastname):
    password = psh.hashPassword(password)

    if userExists(email):
        return False
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO users (email, password, firstname, lastname, lastactivity) VALUES (?,?,?,?,?)", (email, password, firstname, lastname, datetime.now()))
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
        flash("An error occurred while deleting the user.", "error")
        return False

def deleteUserByInactivity():
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cutoff_date = datetime.now() - timedelta(days=180)
    cur.execute("DELETE FROM users WHERE last_activity < ?", (cutoff_date,))
    con.commit()
    con.close()

def updateLastActivity(user_id):
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("UPDATE users SET lastactivity = ? WHERE id = ?", (datetime.now(), user_id))
    con.commit()
    con.close()

## Devlog related functions
def mapDevlogRows(data):
    return [{
        'id': row[0],
        'user_id': row[1],
        'title': row[2],
        'body': html.unescape(row[3]),
        'date': row[4],
        'fullname': row[5]
    } for row in data]

def insertDevlog(title: str, body: str, fullname: str, user_id: int, date: str) -> None:
    safe_title = html.escape(title)
    safe_body = html.escape(body)
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO developer_log (title, body, user_id, date, fullname) VALUES (?, ?, ?, ?, ?)",(safe_title, safe_body, user_id, date, fullname))
    con.commit()
    con.close()

def deleteLogs(user_id, log_id):
    try:
        con = sql.connect(".databaseFiles/database.db")
        cur = con.cursor()
        cur.execute("SELECT user_id FROM developer_log WHERE id = ?", (log_id,))
        log = cur.fetchone()
        if log and log[0] == user_id:
            cur.execute("DELETE FROM developer_log WHERE id = ?", (log_id,))
            con.commit()
            flash("Log deleted successfully.", "success")
        else:
            flash("You do not have permission to delete this log.", "error")
    except Exception as e:
        print(f"Error deleting log: {e}")
        flash("An error occurred while deleting the log.", "error")
    finally:
        if con:
            con.close()
    return redirect(url_for('dashboard'))

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
