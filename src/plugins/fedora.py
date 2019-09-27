import re

distribution = "fedora"
abrtparser = re.compile(r"^Fedora release ([0-9]+) \(([^\)]+)\)$")
guessparser = re.compile(r"\.fc([0-9]+)")
displayrelease = "Fedora release"
gdb_package = "gdb"
gdb_executable = "/usr/bin/gdb"
versionlist = [
    "fc22",
    "fc23",
    "fc24",
    "fc25",
    "fc26",
    "fc27",
    "fc28",
    "fc29",
    "fc30",
    "fc31",
    "fc32",
]

# Find more details about Fedora Mirroring at:
#   https://fedoraproject.org/wiki/Infrastructure/Mirroring
#
# fedora-enchilada is /pub/fedora on http://dl.fedoraproject.org
repos = [
    [
        "rsync://dl.fedoraproject.org/fedora-enchilada/linux/releases/$VER/Everything/$ARCH/os/Packages/*/*.rpm",
        "rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/$VER/Everything/$ARCH/os/Packages/*/*.rpm",
    ],
    [
        "rsync://dl.fedoraproject.org/fedora-enchilada/linux/releases/$VER/Everything/$ARCH/debug/*/*.rpm",
        "rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/$VER/"
        "Everything/$ARCH/debug/tree/Packages/*/*.rpm",
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
