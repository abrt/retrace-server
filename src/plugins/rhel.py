import re
from typing import List

distribution = "rhel"
abrtparser = re.compile(r"^Red Hat Enterprise Linux(?:\s\w+)? release (\d+)(?:\.(\d+))?(?:\s\w+)? \(([^\)]+)\)$")
guessparser = re.compile(r"\.el(\d+)")
displayrelease = "Red Hat Enterprise Linux release"
gpg_keys = [
    "/usr/share/distribution-gpg-keys/epel/RPM-GPG-KEY-EPEL-{release}",
    "/usr/share/distribution-gpg-keys/redhat/RPM-GPG-KEY-redhat{release}-release",
]
gdb_package = "devtoolset-8-gdb"
gdb_executable = "/opt/rh/devtoolset-8/root/usr/bin/gdb"
versionlist = [
    "el1",
    "el2",
    "el3",
    "el4",
    "el5",
    "el6",
    "el7",
    "el8",
]
repos: List[List[str]] = [[]]
