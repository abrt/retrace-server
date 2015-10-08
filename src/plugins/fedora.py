import re

distribution = "fedora"
abrtparser = re.compile("^Fedora release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile("\.fc([0-9]+)")
repos = [
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/releases/$VER/Everything/$ARCH/os/Packages/*/*.rpm",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/$VER/$ARCH/os/Packages/*/*.rpm",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/releases/$VER/Everything/$ARCH/debug/*/*.rpm",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/$VER/$ARCH/debug/*/*.rpm",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/$VER/$ARCH/*.rpm",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/$VER/$ARCH/*/*.rpm",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/$VER/$ARCH/debug/*.rpm",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/$VER/$ARCH/debug/*/*.rpm",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/testing/$VER/$ARCH/*.rpm",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/testing/$VER/$ARCH/*/*.rpm",
  ],
  [
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/testing/$VER/$ARCH/debug/*.rpm",
    "rsync://dl.fedoraproject.org/fedora-enchilada/linux/updates/testing/$VER/$ARCH/debug/*/*.rpm",
  ],
]
