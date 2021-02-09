#! /bin/bash
#########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#########################################################################

# Loads Up Utilities and Commands Variables

source /usr/local/sbin/collect_parms
source /usr/local/sbin/collect_utils

SERVICE="kube_memory"
LOGFILE="${extradir}/${SERVICE}.info"

# This displays the total resident set size per namespace and container,
# the aggregate memory usage per system service, and the platform memory usage.
delimiter ${LOGFILE} "kube-memory"
kube-memory >>${LOGFILE}

exit 0
