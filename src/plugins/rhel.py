import re

distribution = "rhel"
abrtparser = re.compile("^Red Hat Enterprise Linux release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile("\.el([0-9]+)")
displayrelease = "Red Hat Enterprise Linux release"
gdb_package = "devtoolset-4-gdb"
gdb_executable = "/opt/rh/devtoolset-4/root/usr/bin/gdb"
versionlist = [
  "el1",
  "el2",
  "el3",
  "el4",
  "el5",
  "el6",
  "el7",
]
repos = [[]]
