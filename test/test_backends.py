from unittest import mock, TestCase

import retrace.backends.podman
from retrace.backends.podman import LocalPodmanBackend, PodmanContainer
from retrace.config import PODMAN_BIN
from retrace.retrace import RetraceError


class TestPodmanContainer(TestCase):
    CONTAINER_ID = "cefe728950018e14f00cc874d45259742e2925c6ab40e0044a4aedaf1514b660"

    def setUp(self):
        self.container = PodmanContainer(self.CONTAINER_ID)

    def test_short_id(self):
        self.assertEqual(self.container.short_id, "cefe728")

    @mock.patch("retrace.backends.podman.run")
    def test_copy_to(self, mock_run):
        mock_run.return_value.returncode = 0

        self.container.copy_to("/tmp/oldname", "/tmp/newname")

        mock_run.assert_called_once()
        self.assertTupleEqual(mock_run.call_args[0],
                              ([PODMAN_BIN, "cp", "/tmp/oldname",
                                f"{self.CONTAINER_ID}:/tmp/newname"],))

    @mock.patch("retrace.backends.podman.run")
    def test_exec_no_user(self, mock_run):
        mock_run.return_value.returncode = 0

        self.container.exec(["uname", "-r"])

        mock_run.assert_called_once()
        self.assertTupleEqual(mock_run.call_args[0],
                              ([PODMAN_BIN, "exec", self.CONTAINER_ID,
                                "uname", "-r"],))

    @mock.patch("retrace.backends.podman.run")
    def test_exec_with_user(self, mock_run):
        mock_run.return_value.returncode = 0

        self.container.exec(["uname", "-r"], user="retrace")

        mock_run.assert_called_once()
        self.assertTupleEqual(mock_run.call_args[0],
                              ([PODMAN_BIN, "exec", "--user=retrace",
                                self.CONTAINER_ID, "uname", "-r"],))

    @mock.patch("retrace.backends.podman.run")
    def test_stop_and_remove_success(self, mock_run):
        mock_run.return_value.returncode = 0

        self.container.stop_and_remove()

        mock_run.assert_called_once()

    @mock.patch("retrace.backends.podman.run")
    def test_stop_and_remove_failure(self, mock_run):
        mock_run.return_value.returncode = 1

        with self.assertRaises(RetraceError):
            self.container.stop_and_remove()

        mock_run.assert_called_once()


@mock.patch("retrace.backends.podman.PodmanContainer")
class TestLocalPodmanBackend(TestCase):
    CONTAINER_ID = "7d191875746407d0e279d34e8627eb20dec4016ca592bd6b7f05273867e4eb2f"

    @mock.patch("retrace.backends.podman.run")
    def test_start_container(self, mock_run, MockPodmanContainer):
        config = {
                "FafLinkDir": "",
                "RequireGPGCheck": False,
                "UseFafPackages": False,
        }
        image_tag = "retrace-image-14141414"
        taskid = 14141414
        repopath = "/srv/retrace/repos/fedora-39-x86_64"

        mock_container = mock.Mock()
        MockPodmanContainer.return_value = mock_container
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = "Something failed"
        mock_run.return_value.stdout = self.CONTAINER_ID

        backend = LocalPodmanBackend(retrace_config=config)
        container = backend.start_container(image_tag, taskid, repopath)

        self.assertEqual(container, mock_container)
        MockPodmanContainer.assert_called_once_with(self.CONTAINER_ID)
