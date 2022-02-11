from unittest import TestCase

from retrace.util import human_readable_size


class TestGetCanonArch(TestCase):
    def test_zero_bytes(self):
        self.assertEqual(human_readable_size(0), "0.00 B")

    def test_one_byte(self):
        self.assertEqual(human_readable_size(1), "1.00 B")

    def test_one_kilobyte(self):
        self.assertEqual(human_readable_size(1000), "1000.00 B")

    def test_one_kibibyte(self):
        self.assertEqual(human_readable_size(1024), "1.00 kB")

    def test_1025_bytes(self):
        self.assertEqual(human_readable_size(1025), "1.00 kB")

    def test_one_mebibyte(self):
        self.assertEqual(human_readable_size(1024 * 1024), "1.00 MB")

    def test_five_mebibytes(self):
        self.assertEqual(human_readable_size(5 * 1024 * 1024), "5.00 MB")

    def test_one_pebibyte(self):
        self.assertEqual(human_readable_size(1024 ** 5), "1.00 PB")
