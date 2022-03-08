import copy
import re
import shutil
from pathlib import Path
from subprocess import PIPE, STDOUT, run
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

import magic as libmagic

from .config import GZIP_BIN, TAR_BIN, XZ_BIN
from .logging import log_debug, log_info

ARCHIVE_UNKNOWN, ARCHIVE_GZ, ARCHIVE_ZIP, \
    ARCHIVE_BZ2, ARCHIVE_XZ, ARCHIVE_TAR, \
    ARCHIVE_7Z, ARCHIVE_LZOP = range(8)

SUFFIX_MAP: Dict[int, str] = {
    ARCHIVE_GZ: ".gz",
    ARCHIVE_BZ2: ".bz2",
    ARCHIVE_XZ: ".xz",
    ARCHIVE_ZIP: ".zip",
    ARCHIVE_7Z: ".7z",
    ARCHIVE_TAR: ".tar",
    ARCHIVE_LZOP: ".lzop",
    ARCHIVE_UNKNOWN: "",
}

HANDLE_ARCHIVE: Dict[str, Any] = {
    "application/x-xz-compressed-tar": {
        "unpack": [TAR_BIN, "xJf"],
        "size": ([XZ_BIN, "--list", "--robot"],
                 re.compile(r"^totals[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+).*")),
        "type": ARCHIVE_XZ,
    },
    "application/x-gzip": {
        "unpack": [TAR_BIN, "xzf"],
        "size": ([GZIP_BIN, "--list"], re.compile(r"^[^0-9]*[0-9]+[^0-9]+([0-9]+).*$")),
        "type": ARCHIVE_GZ,
    },
    "application/x-tar": {
        "unpack": [TAR_BIN, "xf"],
        "size": (["ls", "-l"],
                 re.compile(r"^[ \t]*[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+"
                            "([0-9]+).*$")),
        "type": ARCHIVE_TAR,
    },
}

SNAPSHOT_SUFFIXES = [".vmss", ".vmsn", ".vmem"]


class UnknownArchiveTypeError(ValueError):
    pass


def add_snapshot_suffix(filename: str, snapshot: Path) -> str:
    """
    Adds a snapshot suffix to the filename.
    """
    suffix = snapshot.suffix
    if suffix in SNAPSHOT_SUFFIXES:
        return filename + suffix

    return filename


def check_archive_type(path: Path, media_type: str) -> bool:
    type_meta = HANDLE_ARCHIVE[media_type]
    return ("type" not in type_meta
            or get_archive_type(path) == type_meta["type"])


def check_run(cmd: List[str]) -> None:
    child = run(cmd, stdout=PIPE, stderr=STDOUT, encoding="utf-8", check=False)
    stdout = child.stdout
    if child.returncode:
        raise Exception("%s exited with %d: %s" % (cmd[0], child.returncode, stdout))


def extract_into(archive: Path, directory: Path) -> None:
    filetype = get_archive_type(archive)
    archive_path = str(archive)
    dir_path = str(directory)

    if filetype == ARCHIVE_GZ:
        check_run(["gunzip", archive_path])
    elif filetype == ARCHIVE_BZ2:
        check_run(["bunzip2", archive_path])
    elif filetype == ARCHIVE_XZ:
        check_run(["unxz", archive_path])
    elif filetype == ARCHIVE_ZIP:
        check_run(["unzip", archive_path, "-d", dir_path])
    elif filetype == ARCHIVE_7Z:
        check_run(["7za", "e", f"-o{dir_path}", archive_path])
    elif filetype == ARCHIVE_TAR:
        check_run(["tar", "-C", dir_path, "-xf", archive_path])
    elif filetype == ARCHIVE_LZOP:
        check_run(["lzop", "-d", archive_path])
    else:
        raise UnknownArchiveTypeError

    if archive.is_file():
        archive.unlink()


def get_archive_type(path: Union[str, Path]) -> int:
    magic = libmagic.open(libmagic.MAGIC_NONE)
    magic.load()
    filetype = magic.file(str(path)).lower()
    log_debug("File type: %s" % filetype)

    if "bzip2 compressed data" in filetype:
        log_debug("bzip2 detected")
        return ARCHIVE_BZ2
    if "gzip compressed data" in filetype or \
            "compress'd data" in filetype:
        log_debug("gzip detected")
        return ARCHIVE_GZ
    if "xz compressed data" in filetype:
        log_debug("xz detected")
        return ARCHIVE_XZ
    if "7-zip archive data" in filetype:
        log_debug("7-zip detected")
        return ARCHIVE_7Z
    if "zip archive data" in filetype:
        log_debug("zip detected")
        return ARCHIVE_ZIP
    if "tar archive" in filetype:
        log_debug("tar detected")
        return ARCHIVE_TAR
    if "lzop compressed data" in filetype:
        log_debug("lzop detected")
        return ARCHIVE_LZOP

    log_debug("unknown file type, unpacking finished")
    return ARCHIVE_UNKNOWN


def get_files_sizes(directory: Union[str, Path]) -> List[Tuple[Path, int]]:
    result: List[Tuple[Path, int]] = []

    for path in Path(directory).iterdir():
        if path.is_file():
            result.append((path, path.stat().st_size))
        elif path.is_dir():
            result += get_files_sizes(path)

    return sorted(result, key=lambda f_s: f_s[1], reverse=True)


def get_supported_mime_types() -> List[str]:
    return list(HANDLE_ARCHIVE.keys())


def is_supported_mime_type(media_type: str) -> bool:
    return media_type in HANDLE_ARCHIVE


def rename_with_suffix(frompath: Path, topath: Path) -> Path:
    suffix = SUFFIX_MAP[get_archive_type(frompath)]

    # check if the file has a snapshot suffix
    # if it does, keep the suffix
    if not suffix:
        suffix = add_snapshot_suffix(suffix, frompath)

    if not topath.suffix == suffix:
        topath = topath.with_suffix(suffix)

    frompath.rename(topath)

    return topath


def unpack(archive: str,
           mime: str,
           targetdir: Optional[Union[str, Path]] = None) -> int:
    cmd = copy.copy(cast(List[str], HANDLE_ARCHIVE[mime]["unpack"]))
    cmd.append(archive)
    if targetdir is not None:
        cmd.append("--directory")
        cmd.append(str(targetdir))

    child = run(cmd, check=False)
    return child.returncode


def unpack_coredump(path: Path, target_name: str) -> None:
    processed: Set[Path] = set()
    parentdir = path.parent
    files = set(f for (f, s) in get_files_sizes(parentdir))
    # Keep unpacking
    while len(files - processed) > 0:
        archive = list(files - processed)[0]
        try:
            extract_into(archive, parentdir)
        except UnknownArchiveTypeError:
            # Skip files that aren't archives.
            continue

        processed.add(archive)

        files = set(f for (f, s) in get_files_sizes(parentdir))

    # If coredump is not present, the biggest file becomes it
    if target_name not in (f.name for f in parentdir.iterdir()):
        biggest_file = get_files_sizes(parentdir)[0][0]
        log_debug(f"Coredump file ‘{target_name}’ not present; using the biggest "
                  f"file, ‘{biggest_file.name}’")
        biggest_file.rename(parentdir / target_name)

    for filename in Path(parentdir).iterdir():
        if filename.is_dir():
            shutil.rmtree(filename)


def unpack_vmcore(path: Path) -> None:
    vmcore_file = "vmcore"
    parentdir = path.parent
    archivebase = parentdir / "archive"
    archive = rename_with_suffix(path, archivebase)

    while True:
        files = set(f for (f, s) in get_files_sizes(parentdir))
        try:
            extract_into(archive, parentdir)
        except UnknownArchiveTypeError:
            log_info(f"File {archive} is not an archive")
            break

        files_sizes = get_files_sizes(parentdir)
        newfiles = [f for (f, s) in files_sizes if f.suffix != ".vmem"]
        diff = set(newfiles) - files
        vmcore_candidate = 0
        while vmcore_candidate < len(newfiles) and newfiles[vmcore_candidate] not in diff:
            vmcore_candidate += 1

        # rename files with .vmem extension to vmcore.vmem
        for sibling in Path(parentdir).iterdir():
            if sibling.suffix == ".vmem":
                sibling.rename(Path(parentdir, vmcore_file + sibling.suffix))

        if len(diff) > 1:
            archive = rename_with_suffix(newfiles[vmcore_candidate], archivebase)
            for filename in newfiles:
                if filename not in diff or \
                   filename == newfiles[vmcore_candidate]:
                    continue

                filename.unlink()

        elif len(diff) == 1:
            archive = rename_with_suffix(diff.pop(), archivebase)

        # just be explicit here - if no file changed, an archive
        # has most probably been unpacked to a file with same name
        else:
            pass

        for filename in Path(parentdir).iterdir():
            if filename.is_dir():
                shutil.rmtree(filename)

    vmcore_file = add_snapshot_suffix(vmcore_file, archive)
    archive.rename(parentdir / vmcore_file)


def unpacked_size(archive: str, mime: str) -> Optional[int]:
    command, parser = HANDLE_ARCHIVE[mime]["size"]
    lines = run(command + [archive], stdout=PIPE, encoding="utf-8", check=False).stdout.split("\n")
    for line in lines:
        match = parser.match(line)
        if match:
            return int(match.group(1))

    return None
