import re

distribution = "centos"
abrtparser = re.compile(r"^CentOS Linux release (\d+)(?:\.(\d+)\.(\d+))? \(([^\)]+)\)$")
guessparser = re.compile(r"\.el(\d+)")
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
