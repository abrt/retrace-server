import re
from pathlib import Path
from subprocess import PIPE, STDOUT, run
from typing import Dict, Optional, Set

ARCHITECTURES: Set[str] = {
    "src", "noarch", "i386", "i486", "i586", "i686", "x86_64",
    "s390", "s390x", "ppc", "ppc64", "ppc64le", "ppc64iseries",
    "armel", "armhfp", "armv5tel", "armv7l", "armv7hl",
    "armv7hnl", "aarch64", "sparc", "sparc64", "mips4kec",
    "ia64"
}

# armhfp is not correct, but there is no way to distinguish armv5/armv6/armv7 coredumps
# as armhfp (RPM armv7hl) is the only supported now, let's approximate arm = armhfp

# "arm" has been intentionally removed - when guessing architecture, it matches
# "alarm" or "hdparm" and thus leads to wrong results.
# As soon as plain "arm" needs to be supported, this needs to be solved properly.
ARCH_MAP: Dict[str, Set[str]] = {
    "i386": {"i386", "i486", "i586", "i686"},
    "armhfp": {"armhfp", "armel", "armv5tel", "armv7l", "armv7hl", "armv7hnl"},
    "x86_64": {"x86_64"},
    "s390x": {"s390x"},
    "ppc64": {"ppc64"},
    "ppc64le": {"ppc64le"},
    "aarch64": {"aarch64"},
}

CORE_ARCH_PARSER = re.compile(r"core file,? .*(x86-64|80386|ARM|aarch64|IBM S/390|64-bit PowerPC)")


def get_canon_arch(arch: str) -> str:
    for canon_arch, derived_archs in ARCH_MAP.items():
        if arch in derived_archs:
            return canon_arch

    return arch


def guess_arch(coredump_path: Path) -> Optional[str]:
    output = run(["file", str(coredump_path)], stdout=PIPE, encoding="utf-8",
                 check=False).stdout
    match = CORE_ARCH_PARSER.search(output)
    if match:
        if match.group(1) == "80386":
            return "i386"
        if match.group(1) == "x86-64":
            return "x86_64"
        if match.group(1) == "ARM":
            # hack - There is no reliable way to determine which ARM
            # version the coredump is. At the moment we only support
            # armv7hl / armhfp - let's approximate arm = armhfp
            return "armhfp"
        if match.group(1) == "aarch64":
            return "aarch64"
        if match.group(1) == "IBM S/390":
            return "s390x"
        if match.group(1) == "64-bit PowerPC":
            if "LSB" in output:
                return "ppc64le"

            return "ppc64"

    result: Optional[str] = None
    lines = run(["strings", str(coredump_path)],
                stdout=PIPE, stderr=STDOUT, encoding="utf-8",
                check=False).stdout.splitlines()
    for line in lines:
        for canon_arch, derived_archs in ARCH_MAP.items():
            if any(arch in line for arch in derived_archs):
                result = canon_arch
                break

        if result is not None:
            break

    # "ppc64le" matches both ppc64 and ppc64le
    # if file magic says little endian, fix it
    if result == "ppc64" and "LSB" in output:
        result = "ppc64le"

    return result
