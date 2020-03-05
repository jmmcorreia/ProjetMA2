from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import NullPool
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLite3Connection


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()


Base = declarative_base()
engine = create_engine('sqlite:///test.db', echo=True, poolclass=NullPool, connect_args={'timeout': 15})  # connect_args={'check_same_thread': False}
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

Session.configure(bind=engine)  # once engine is available
