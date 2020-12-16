import copy
import os
import re
import errno
import ftplib
import gettext
import smtplib

from pathlib import Path
from subprocess import run, PIPE
from typing import cast, Any, Callable, Dict, List, Optional, SupportsFloat, Tuple, Union
from dnf.subject import Subject
from hawkey import FORM_NEVRA

from .config import Config, DF_BIN, GZIP_BIN, TAR_BIN, XZ_BIN

GETTEXT_DOMAIN = "retrace-server"

DF_OUTPUT_PARSER = re.compile(r"^([^ ^\t]*)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+%)[ \t]+(.*)$")

# architecture (i386, x86_64, armv7hl, mips4kec)
INPUT_ARCH_PARSER = re.compile(r"^[\w\d_]+$")
# characters, numbers, dash (utf-8, iso-8859-2 etc.)
INPUT_CHARSET_PARSER = re.compile(r"^([\w\d-]+)(,.*)?$")
# en_GB, sk-SK, cs, fr etc.
INPUT_LANG_PARSER = re.compile(r"^([a-z]{2}([_\-][A-Z]{2})?)(,.*)?$")
# characters allowed by Fedora Naming Guidelines
INPUT_PACKAGE_PARSER = re.compile(r"^[\w\d_.+-]+([1-9][0-9]*:)?[\w\d.+~-]+$")
# name-version-arch (fedora-16-x86_64, rhel-6.2-i386, opensuse-12.1-x86_64)
INPUT_RELEASEID_PARSER = re.compile(r"^[\w\d]+-[\w\d.]+-[\w\d_]+$")

UNITS = ["B", "kB", "MB", "GB", "TB", "PB", "EB"]
URL_PARSER = re.compile(r"^/([0-9]+)/?")

ARCHIVE_UNKNOWN, ARCHIVE_GZ, ARCHIVE_ZIP, \
  ARCHIVE_BZ2, ARCHIVE_XZ, ARCHIVE_TAR, \
  ARCHIVE_7Z, ARCHIVE_LZOP = range(8)

HANDLE_ARCHIVE = {
    "application/x-xz-compressed-tar": {
        "unpack": [TAR_BIN, "xJf"],
        "size": ([XZ_BIN, "--list", "--robot"],
                 re.compile(r"^totals[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+).*")),
        "type": ARCHIVE_XZ,
    },

    "application/x-gzip": {
        "unpack": [TAR_BIN, "xzf"],
        "size": ([GZIP_BIN, "--list"], re.compile(r"^[^0-9]*[0-9]+[^0-9]+([0-9]+).*$")),
        "type": ARCHIVE_GZ,
    },

    "application/x-tar": {
        "unpack": [TAR_BIN, "xf"],
        "size": (["ls", "-l"],
                 re.compile(r"^[ \t]*[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+([0-9]+).*$")),
        "type": ARCHIVE_TAR,
    },
}


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
                stdout=PIPE, encoding='utf-8', check=False).stdout.split("\n")
    for line in lines:
        match = DF_OUTPUT_PARSER.match(line)
        if match:
            return int(match.group(4))

    return None


def ftp_init() -> ftplib.FTP:
    CONFIG = Config()
    if CONFIG["FTPSSL"]:
        ftp = ftplib.FTP_TLS(CONFIG["FTPHost"])
        ftp.prot_p()
    else:
        ftp = ftplib.FTP(CONFIG["FTPHost"])

    ftp.login(CONFIG["FTPUser"], CONFIG["FTPPass"])
    ftp.cwd(CONFIG["FTPDir"])

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
    while size > 1024.0 and unit < len(UNITS) - 1:
        unit += 1
        size /= 1024.0

    return "%.2f %s" % (size, UNITS[unit])


def parse_http_gettext(lang: str, charset: str) -> Callable[[str], str]:
    result = lambda x: x
    lang_match = INPUT_LANG_PARSER.match(lang)
    charset_match = INPUT_CHARSET_PARSER.match(charset)
    if lang_match and charset_match:
        try:
            result = gettext.translation(GETTEXT_DOMAIN,
                                         languages=[lang_match.group(1)],
                                         codeset=charset_match.group(1)).gettext
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
     result["arch"]) = splitFilename(name + ".mockarch.rpm")

    return result


def response(start_response: Callable[[str, List[Tuple[str, str]]], None],
             status: str,
             body: Union[bytes, str] = "",
             extra_headers: List[Tuple[str, str]] = []) -> List[bytes]:
    if isinstance(body, str):
        body = body.encode("utf-8")

    start_response(status, [("Content-Type", "text/plain"), ("Content-Length", "%d" % len(body))] + extra_headers)
    return [body]


def send_email(frm: str, to: Union[str, List[str]], subject: str, body: str) -> None:
    if isinstance(to, list):
        to = ",".join(to)

    msg = "From: %s\n" \
          "To: %s\n" \
          "Subject: %s\n" \
          "\n" \
          "%s" % (frm, to, subject, body)

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(frm, to, msg)
    smtp.close()


def splitFilename(filename: str) -> Union[Tuple[None, None, None, None, None], Tuple[str, str, str, str, str]]:
    """
    Pass in a standard style rpm fullname

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
    """

    if filename[-4:] == '.rpm':
        filename = filename[:-4]

    subject = Subject(filename)
    possible_nevra = list(subject.get_nevra_possibilities(forms=FORM_NEVRA))
    if possible_nevra:
        nevra = possible_nevra[0]
    else:
        return None, None, None, None, None

    return nevra.name, nevra.version, nevra.release, nevra.epoch, nevra.arch


def unpack(archive: str, mime: str, targetdir: Optional[str] = None) -> int:
    cmd = copy.copy(cast(List[str], HANDLE_ARCHIVE[mime]["unpack"]))
    cmd.append(archive)
    if targetdir is not None:
        cmd.append("--directory")
        cmd.append(targetdir)

    child = run(cmd, check=False)
    return child.returncode


def unpacked_size(archive: str, mime: str) -> Optional[int]:
    command, parser = HANDLE_ARCHIVE[mime]["size"]
    lines = run(command + [archive], stdout=PIPE, encoding='utf-8', check=False).stdout.split("\n")
    for line in lines:
        match = parser.match(line)
        if match:
            return int(match.group(1))

    return None
