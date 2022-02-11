import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from .retrace import CONFIG
from .util import parse_rpm_name


def init_crashstats_db() -> sqlite3.Connection:
    # create the database group-writable and world-readable
    old_umask = os.umask(0o113)
    con = sqlite3.connect(os.path.join(CONFIG["SaveDir"], CONFIG["DBFile"]))
    os.umask(old_umask)

    query = con.cursor()
    query.execute("PRAGMA foreign_keys = ON")
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      tasks(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid, package, version,
      arch, starttime NOT NULL, duration NOT NULL, coresize, status NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      success(taskid REFERENCES tasks(id), pre NOT NULL, post NOT NULL,
              rootsize NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      packages(id INTEGER PRIMARY KEY AUTOINCREMENT,
               name NOT NULL, version NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      packages_tasks(pkgid REFERENCES packages(id),
                     taskid REFERENCES tasks(id))
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      buildids(taskid REFERENCES tasks(id), soname, buildid NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      reportfull(requesttime NOT NULL, ip NOT NULL)
    """)
    con.commit()

    return con


def save_crashstats(stats: Dict[str, Any], con: Optional[sqlite3.Connection] = None) -> int:
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO tasks (taskid, package, version, arch,
      starttime, duration, coresize, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      """,
                  (stats["taskid"], stats["package"], stats["version"],
                   stats["arch"], stats["starttime"], stats["duration"],
                   stats["coresize"], stats["status"]))

    con.commit()
    if close:
        con.close()

    return query.lastrowid


def save_crashstats_success(statsid: int, pre: int, post: int, rootsize: int,
                            con: Optional[sqlite3.Connection] = None) -> None:
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO success (taskid, pre, post, rootsize)
      VALUES (?, ?, ?, ?)
      """,
                  (statsid, pre, post, rootsize))

    con.commit()
    if close:
        con.close()


def save_crashstats_packages(statsid: int,
                             packages: List[str],
                             con: Optional[sqlite3.Connection] = None) -> None:
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    for package in packages:
        pkgdata = parse_rpm_name(package)
        if pkgdata["name"] is None:
            continue

        ver = "%s-%s" % (pkgdata["version"], pkgdata["release"])
        query.execute("SELECT id FROM packages WHERE name = ? AND version = ?",
                      (pkgdata["name"], ver))
        row = query.fetchone()
        if row:
            pkgid = row[0]
        else:
            query.execute("INSERT INTO packages (name, version) VALUES (?, ?)",
                          (pkgdata["name"], ver))
            pkgid = query.lastrowid

        query.execute("""
          INSERT INTO packages_tasks (taskid, pkgid) VALUES (?, ?)
          """, (statsid, pkgid))

    con.commit()
    if close:
        con.close()


def save_crashstats_build_ids(statsid: int, buildids: List[Tuple[str, str]],
                              con: Optional[sqlite3.Connection] = None) -> None:
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    for soname, buildid in buildids:
        query.execute("""
          INSERT INTO buildids (taskid, soname, buildid)
          VALUES (?, ?, ?)
          """,
                      (statsid, soname, buildid))

    con.commit()
    if close:
        con.close()


def save_crashstats_reportfull(ip_addr: str,
                               con: Optional[sqlite3.Connection] = None) -> None:
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO reportfull (requesttime, ip)
      VALUES (?, ?)
      """,
                  (int(time.time()), ip_addr))

    con.commit()
    if close:
        con.close()
