import sqlite3

DB_PATH="data/netsentry.db"

def init_db():
    conn=sqlite3.connect(DB_PATH)
    cursor= conn.cursor()
    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS packet(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            flags TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_packet(conn,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,flags):
    cursor=conn.cursor()
    cursor.execute("""
    INSERT into packet(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,flags)
    VALUES(?,?,?,?,?,?,?)
    """,(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,flags)
    )
    conn.commit()
        