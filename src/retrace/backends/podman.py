import os.path
from pathlib import Path
from subprocess import CompletedProcess, DEVNULL, PIPE, run, STDOUT
from typing import List, Optional, Union

from retrace.retrace import (log_debug,
                             log_info,
                             RETRACE_GPG_KEYS,
                             RetraceError)
from retrace.config import Config, PODMAN_BIN


class PodmanContainer:
    def __init__(self, container_id: str) -> None:
        self.id = container_id

    def copy_to(self, src: Union[str, Path], dst: Union[str, Path]) -> None:
        proc = run([PODMAN_BIN, "cp", str(src), f"{self.id}:{dst}"],
                   stdout=DEVNULL, stderr=PIPE, encoding="utf-8", check=False)

        if proc.returncode:
            raise RetraceError(
                f"Could not copy file ‘{src}’ to container: {proc.stderr}")

    def exec(self, cmd: List[str], user: Optional[str] = None) \
            -> CompletedProcess:
        args = [PODMAN_BIN, "exec"]

        if user is not None:
            args.append(f"--user={user}")

        args.append(self.id)
        args.extend(cmd)

        return run(args, stderr=STDOUT, stdout=PIPE, encoding="utf-8", check=False)

    @property
    def short_id(self) -> str:
        return self.id[:7]

    def stop_and_remove(self) -> None:
        proc = run([PODMAN_BIN, "rm", "--force", self.id],
                   stderr=PIPE, stdout=DEVNULL, encoding="utf-8", check=False)

        if proc.returncode:
            raise RetraceError(f"Could not stop container {self.short_id}: {proc.stderr}")

        log_info(f"Container {self.short_id} stopped and removed")

    def __enter__(self) -> "PodmanContainer":
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.stop_and_remove()


class LocalPodmanBackend:
    def __init__(self, retrace_config: Config):
        self.config = retrace_config

    def start_container(self, image_tag: str, taskid: int, repopath: str,
                        use_debuginfod: bool = False) -> PodmanContainer:
        run_call = [PODMAN_BIN, "run",
                    "--quiet",
                    "--detach",
                    "--interactive",
                    "--tty",
                    "--sdnotify=ignore",
                    f"--name=retrace-{taskid}"]

        if use_debuginfod:
            # TODO: Do we want a special config variable for this path?
            debuginfod_cache_dir = os.path.join(self.config["RepoDir"], "debuginfod")
            run_call.append(f"--volume={debuginfod_cache_dir}:/tmp/debuginfod:z")
        else:
            run_call.append(f"--volume={repopath}:{repopath}:ro")

        if self.config["RequireGPGCheck"]:
            run_call.append("--volume={0}:{0}:ro".format(RETRACE_GPG_KEYS))

        if self.config["UseFafPackages"]:
            log_debug("Using FAF repository")
            run_call.append("--volume={0}:{0}:ro".format(self.config["FafLinkDir"]))

        run_call.append(image_tag)

        child = run(run_call, stderr=PIPE, stdout=PIPE, encoding="utf-8",
                    check=False)

        if child.returncode:
            raise RetraceError(f"Could not start container: {child.stderr}")

        container_id = child.stdout.strip()
        container = PodmanContainer(container_id)
        log_info(f"Container {container.short_id} started")

        return container
