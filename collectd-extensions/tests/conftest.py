#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Shared test fixtures for collectd-extensions tests.

This conftest.py ensures that all mocked modules are registered once using
setdefault(), preventing sys.modules pollution when pytest runs multiple
test files in the same process.
"""

import os
import sys
from unittest.mock import MagicMock

# Modules that need to be mocked because they are either C extensions
# (collectd), platform-specific, or not available in the test environment.
_MOCKED_MODULES = [
    'collectd',
    'tsconfig',
    'tsconfig.tsconfig',
    'plugin_common',
    'fm_api',
    'fm_api.constants',
    'fm_api.fm_api',
    'ptp_interface',
    'ptp_gnss_monitor',
    'cgu_handler',
    'pynetlink',
    'oslo_utils',
    'oslo_utils.timeutils',
    'oslo_concurrency',
    'oslo_concurrency.processutils',
    'gps',
    'httplib2',
]

for _mod in _MOCKED_MODULES:
    sys.modules.setdefault(_mod, MagicMock())

# Ensure the src directory is on the path for all tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
