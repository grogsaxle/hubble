# -*- coding: utf-8 -*-
from hubblestack.utils.dedup_filter import DedupFilter

# Import Salt Testing libs
from tests.support.unit import TestCase


class DedupFilterTestCase(TestCase):
    def test_add(self):
        d = DedupFilter(maxlen=3)
        self.assertFalse(d.filter('alice'))
        self.assertTrue(d.filter('alice'))
        self.assertFalse(d.filter('bob'))

