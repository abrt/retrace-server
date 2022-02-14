from unittest import TestCase

from retrace.architecture import get_canon_arch


class TestGetCanonArch(TestCase):
    def test_i386(self):
        self.assertEqual(get_canon_arch("i386"), "i386")
        self.assertEqual(get_canon_arch("i686"), "i386")

    def test_armhfp(self):
        self.assertEqual(get_canon_arch("armhfp"), "armhfp")
        self.assertEqual(get_canon_arch("armv7hl"), "armhfp")

    def test_x86_64(self):
        self.assertEqual(get_canon_arch("x86_64"), "x86_64")

    def test_ppc64(self):
        self.assertEqual(get_canon_arch("ppc64"), "ppc64")

    def test_aarch64(self):
        self.assertEqual(get_canon_arch("aarch64"), "aarch64")

    def test_unknown(self):
        self.assertEqual(get_canon_arch("unknown"), "unknown")
