#!/usr/bin/env python

"""
Copyright (c) 2020 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import setuptools

setuptools.setup(
    name='kube_cpusets',
    version='1.0.0',
    description='display kubernetes containers cpusets per numa node',
    license='Apache-2.0',
    packages=['kube_cpusets'],
    entry_points={
        'console_scripts': [
            'kube-cpusets = kube_cpusets.kube_cpusets:main',
        ]}
)
