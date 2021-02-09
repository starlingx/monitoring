#!/usr/bin/env python

"""
Copyright (c) 2021 Wind River Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
import setuptools
setuptools.setup(
    name='kube_memory',
    version='1.0.0',
    description='display services and kubernetes containers memory usage',
    license='Apache-2.0',
    packages=['kube_memory'],
    entry_points={
        'console_scripts': [
            'kube-memory = kube_memory.kube_memory:main',
        ]}
)
