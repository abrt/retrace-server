from subprocess import DEVNULL, PIPE
from unittest import mock, TestCase

import retrace.backends.podman
from retrace.backends.podman import LocalPodmanBackend, PodmanContainer
from retrace.config import PODMAN_BIN


class TestPodmanContainer(TestCase):
    CONTAINER_ID = 'cefe728950018e14f00cc874d45259742e2925c6ab40e0044a4aedaf1514b660'

    def setUp(self):
        self.container = PodmanContainer(self.CONTAINER_ID)

    def test_short_id(self):
        self.assertEqual(self.container.short_id, 'cefe728')

    @mock.patch('retrace.backends.podman.run')
    def test_copy_to(self, mock_run):
        mock_run.return_value.returncode = 0
        self.container.copy_to('/tmp/oldname', '/tmp/newname')

        mock_run.assert_called_once_with([
            PODMAN_BIN,
            'cp',
            '/tmp/oldname',
            f'{self.CONTAINER_ID}:/tmp/newname'
        ], stdout=DEVNULL, stderr=PIPE, encoding='utf-8', check=False)
