import re
from typing import List

distribution = "centos"
abrtparser = re.compile(r"^CentOS Linux release (\d+)(?:\.(\d+)\.(\d+))? \(([^\)]+)\)$")
guessparser = re.compile(r"\.el(\d+)")
displayrelease = "CentOS release"
gdb_package = "gdb"
gdb_executable = "/usr/bin/gdb"
gpg_keys = [
    "/usr/share/distribution-gpg-keys/epel/RPM-GPG-KEY-EPEL-{release}",
    "/usr/share/distribution-gpg-keys/centos/RPM-GPG-KEY-CentOS-{release}",
]
versionlist = [
    "el6",
    "el7",
    "el8",
    "el9",
]
repos: List[List[str]] = [[]]
