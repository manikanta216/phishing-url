import os
import sqlite3
import pymysql
import pymysql.cursors
from config import Config

SQLITE_DB_PATH = os.path.join(os.path.dirname(__file__), 'phishshield_fallback.db')

def init_sqlite_db():
    """Initializes a local SQLite fallback database if MySQL is unavailable."""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            domain TEXT,
            ip_address TEXT,
            url_length INTEGER,
            is_https INTEGER DEFAULT 0,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

def get_db_connection():
    """Attempts MySQL connection, falls back to SQLite dict connection if MySQL fails."""
    try:
        connection = pymysql.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        return connection, 'mysql'
    except Exception:
        init_sqlite_db()
        conn = sqlite3.connect(SQLITE_DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn, 'sqlite'

def create_user(name, email, username, password_hash):
    """Inserts a new user into the database."""
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        sql = "INSERT INTO users (name, email, username, password_hash) VALUES (%s, %s, %s, %s)" if db_type == 'mysql' else \
              "INSERT INTO users (name, email, username, password_hash) VALUES (?, ?, ?, ?)"
        cursor.execute(sql, (name, email, username, password_hash))
        if db_type == 'sqlite':
            conn.commit()
            last_id = cursor.lastrowid
        else:
            last_id = cursor.lastrowid
        return last_id
    finally:
        conn.close()

def get_user_by_username(username):
    """Retrieves a user by username."""
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        sql = "SELECT * FROM users WHERE username = %s" if db_type == 'mysql' else \
              "SELECT * FROM users WHERE username = ?"
        cursor.execute(sql, (username,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def save_scan(user_id, url, prediction, confidence_score, domain, ip_address, url_length, is_https):
    """Saves a URL scan result into scan_history."""
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        sql = """
            INSERT INTO scan_history (user_id, url, prediction, confidence_score, domain, ip_address, url_length, is_https)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """ if db_type == 'mysql' else """
            INSERT INTO scan_history (user_id, url, prediction, confidence_score, domain, ip_address, url_length, is_https)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(sql, (user_id, url, prediction, confidence_score, domain, ip_address, url_length, 1 if is_https else 0))
        if db_type == 'sqlite':
            conn.commit()
            last_id = cursor.lastrowid
        else:
            last_id = cursor.lastrowid
        return last_id
    finally:
        conn.close()

def get_scan_history(user_id):
    """Retrieves scan history for a given user ordered by scanned_at DESC."""
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        sql = "SELECT * FROM scan_history WHERE user_id = %s ORDER BY scanned_at DESC" if db_type == 'mysql' else \
              "SELECT * FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC"
        cursor.execute(sql, (user_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
