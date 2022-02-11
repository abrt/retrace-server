import errno
import ftplib
import gettext
import os
import re
import smtplib
from pathlib import Path
from subprocess import run, PIPE
from typing import Any, Callable, Dict, List, Optional, SupportsFloat, Tuple, Union

from dnf.subject import Subject
from hawkey import FORM_NEVRA

from .config import Config, DF_BIN

GETTEXT_DOMAIN = "retrace-server"

DF_OUTPUT_PARSER = re.compile(r"^([^ ^\t]*)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+%)[ \t]+(.*)$")

# architecture (i386, x86_64, armv7hl, mips4kec)
INPUT_ARCH_PARSER = re.compile(r"^\w+$", re.ASCII)
# characters, numbers, dash (utf-8, iso-8859-2 etc.)
INPUT_CHARSET_PARSER = re.compile(r"^([a-zA-Z0-9-]+)(,.*)?$")
# en_GB, sk-SK, cs, fr etc.
INPUT_LANG_PARSER = re.compile(r"^([a-z]{2}([_\-][A-Z]{2})?)(,.*)?$")
# characters allowed by Fedora Naming Guidelines
INPUT_PACKAGE_PARSER = re.compile(r"^[\w.+-]+([1-9][0-9]*:)?[a-zA-Z0-9.+~-]+$", re.ASCII)
# name-version-arch (fedora-16-x86_64, rhel-6.2-i386, opensuse-12.1-x86_64)
INPUT_RELEASEID_PARSER = re.compile(r"^[a-zA-Z0-9]+-[a-zA-Z0-9.]+-\w+$", re.ASCII)

UNITS = ["B", "kB", "MB", "GB", "TB", "PB", "EB"]
URL_PARSER = re.compile(r"^/([0-9]+)/?")

def lock(lockfile: Path) -> bool:
    try:
        fd = os.open(lockfile, os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as ex:
        if ex.errno == errno.EEXIST:
            return False
        raise ex

    os.close(fd)
    return True


def unlock(lockfile: Path) -> bool:
    try:
        if lockfile.stat().st_size == 0:
            lockfile.unlink()
    except OSError:
        return False

    return True


def free_space(path: str) -> Optional[int]:
    lines = run([DF_BIN, "-B", "1", path],
                stdout=PIPE, encoding="utf-8", check=False).stdout.split("\n")
    for line in lines:
        match = DF_OUTPUT_PARSER.match(line)
        if match:
            return int(match.group(4))

    return None


def ftp_init() -> ftplib.FTP:
    config = Config()
    if config["FTPSSL"]:
        ftp = ftplib.FTP_TLS(config["FTPHost"])
        ftp.prot_p()
    else:
        ftp = ftplib.FTP(config["FTPHost"])

    ftp.login(config["FTPUser"], config["FTPPass"])
    ftp.cwd(config["FTPDir"])

    return ftp


def ftp_close(ftp: ftplib.FTP) -> None:
    try:
        ftp.quit()
    except ftplib.all_errors:
        ftp.close()


def ftp_list_dir(ftpdir: str = "/", ftp: Optional[ftplib.FTP] = None) -> List[str]:
    close = False
    if ftp is None:
        ftp = ftp_init()
        close = True

    result = [f.lstrip("/") for f in ftp.nlst(ftpdir)]

    if close:
        ftp_close(ftp)

    return result


def human_readable_size(bytesize: SupportsFloat) -> str:
    size = float(bytesize)
    unit = 0
    while size >= 1024.0 and unit < len(UNITS) - 1:
        unit += 1
        size /= 1024.0
    return "%.2f %s" % (size, UNITS[unit])


def parse_http_gettext(lang: str, charset: str) -> Callable[[str], str]:
    result = lambda x: x
    lang_match = INPUT_LANG_PARSER.match(lang)
    charset_match = INPUT_CHARSET_PARSER.match(charset)
    if lang_match and charset_match:
        try:
            result = gettext.translation(
                GETTEXT_DOMAIN,
                languages=[lang_match.group(1)]
            ).gettext
        except OSError:
            pass

    return result


def parse_rpm_name(name: str) -> Dict[str, Any]:
    result = {
        "epoch": 0,
        "name": None,
        "version": "",
        "release": "",
        "arch": "",
    }
    (result["name"],
     result["version"],
     result["release"],
     result["epoch"],
     result["arch"]) = split_filename(name + ".mockarch.rpm")

    return result


def response(start_response: Callable[[str, List[Tuple[str, str]]], None],
             status: str,
             body: Union[bytes, str] = "",
             extra_headers: Optional[List[Tuple[str, str]]] = None) -> List[bytes]:
    if isinstance(body, str):
        body = body.encode("utf-8")

    headers = [("Content-Type", "text/plain"),
               ("Content-Length", "%d" % len(body))]
    if extra_headers is not None:
        headers.extend(extra_headers)

    start_response(status, headers)
    return [body]


def send_email(frm: str, to: Union[str, List[str]], subject: str, body: str) -> None:
    if isinstance(to, list):
        to = ",".join(to)

    msg = (f"From: {frm}\n"
           f"To: {to}\n"
           f"Subject: {subject}\n"
           f"\n"
           f"{body}")

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(frm, to, msg)
    smtp.close()


def split_filename(filename: str) -> Union[Tuple[None, None, None, None, None], Tuple[str, str, str, str, str]]:
    """
    Pass in a standard style rpm fullname

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
    """

    if filename.endswith('.rpm'):
        filename = filename[:-4]

    subject = Subject(filename)
    possible_nevra = list(subject.get_nevra_possibilities(forms=FORM_NEVRA))
    if possible_nevra:
        nevra = possible_nevra[0]
    else:
        return None, None, None, None, None

    return nevra.name, nevra.version, nevra.release, nevra.epoch, nevra.arch
