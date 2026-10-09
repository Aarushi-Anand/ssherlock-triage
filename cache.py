import sqlite3, json, time


def init_db():
    conn = sqlite3.connect("cache.db")
    conn.execute("CREATE TABLE IF NOT EXISTS cache (ip TEXT PRIMARY KEY, data TEXT, ts REAL)")
    return conn

def get_cached(conn, ip, max_age=86400):
    row = conn.execute("SELECT data, ts FROM cache WHERE ip = ?", (ip,)).fetchone()
    if row and time.time() - row[1] < max_age:
        return json.loads(row[0])
    return None

def save_cache(conn, ip, data):
    conn.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?)", (ip, json.dumps(data), time.time()),)
    conn.commit()