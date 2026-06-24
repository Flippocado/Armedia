import os
import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/messenger")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_connection():
    conn = psycopg2.connect(DATABASE_URL)
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def init_db():
    with open(SCHEMA_PATH, "r") as f:
        schema = f.read()
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(schema)
    conn.commit()
    conn.close()
