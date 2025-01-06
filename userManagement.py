import sqlite3 as sql
import bcrypt

def insertUser(username, password):
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?,?)",
        (username, password)
    )
    con.commit()
    con.close()

### example
def getUsers():
    con = sql.connect(".databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM id7-tusers")
    con.close()
    return cur

