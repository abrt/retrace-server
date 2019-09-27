import re

distribution = "centos"
abrtparser = re.compile(r"^CentOS Linux release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile(r"\.el([0-9]+)")
displayrelease = "CentOS release"
gdb_package = "gdb"
gdb_executable = "/usr/bin/gdb"
versionlist = [
    "el6",
    "el7",
    "el8",
]
repos = [
    []
]
