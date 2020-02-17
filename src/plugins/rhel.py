import re

distribution = "rhel"
abrtparser = re.compile(r"^Red Hat Enterprise Linux(?:\s\w+)? release (\d+)(?:\.(\d+))?(?:\s\w+)? \(([^\)]+)\)$")
guessparser = re.compile(r"\.el(\d+)")
displayrelease = "Red Hat Enterprise Linux release"
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
repos = [[]]
