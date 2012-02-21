import re

distribution = "fedora"
abrtparser = re.compile("^Fedora release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile("\.fc([0-9]+)")
repos = [
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/releases/$VER/Everything/$ARCH/os/Packages/*",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/$VER/$ARCH/os/Packages/*/*",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/releases/$VER/Everything/$ARCH/debug/*",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/$VER/$ARCH/debug/*/*",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/$VER/$ARCH/*",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/$VER/$ARCH/debug/*",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/testing/$VER/$ARCH/*",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/testing/$VER/$ARCH/debug/*",
  ],
]
