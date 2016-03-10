import re

distribution = "fedora"
abrtparser = re.compile("^Fedora release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile("\.fc([0-9]+)")
displayrelease = "Fedora release"
versionlist = [
  "fc1",
  "fc2",
  "fc3",
  "fc4",
  "fc5",
  "fc6",
  "fc7",
  "fc8",
  "fc9",
  "fc10",
  "fc11",
  "fc12",
  "fc13",
  "fc14",
  "fc15",
  "fc16",
  "fc17",
  "fc18",
  "fc19",
  "fc20",
  "fc21",
  "fc22",
  "fc23",
  "fc24",
]
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
