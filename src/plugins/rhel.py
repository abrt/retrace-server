import re

distribution = "rhel"
abrtparser = re.compile("^Red Hat Enterprise Linux release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile("\.el([0-9]+)")
displayrelease = "Red Hat Enterprise Linux release"
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
