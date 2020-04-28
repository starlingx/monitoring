#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2020 Wind River Systems, Inc.
#

import testtools


class KubeCpusetsTestCase(testtools.TestCase):

    # NOTE(jgauld): Suggest add basic cpuset parsing tests.
    # /sys/devices/system/cpu/isolated
    def test_isolated_cpusets_parse(self):
        pass
        # kube_cpusets.kube_cpusets.get_isolated_cpuset()
