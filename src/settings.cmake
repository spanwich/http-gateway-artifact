#
# Copyright 2025
# HTTP Gateway x86 - Pure CAmkES Settings
#
# 5-component HTTP gateway ported from BCM2837 to x86_64
# E1000Driver <-> TlsValidator <-> LwipProxy <-> HttpValidator <-> WebApp
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

set(project_dir "${CMAKE_CURRENT_LIST_DIR}/../")
file(GLOB project_modules ${project_dir}/*)
list(
    APPEND
        CMAKE_MODULE_PATH
        ${project_dir}/../kernel
        ${project_dir}/../tools/seL4/cmake-tool/helpers/
        ${project_dir}/../tools/seL4/elfloader-tool/
        ${project_modules}
)

set(SEL4_CONFIG_DEFAULT_ADVANCED ON)
set(CAMKES_CONFIG_DEFAULT_ADVANCED ON)
mark_as_advanced(CMAKE_INSTALL_PREFIX)

include(application_settings)

# Include easy settings for platform configuration
include(${CMAKE_CURRENT_LIST_DIR}/easy-settings.cmake)

# Kernel settings for x86 bare-metal (NO HYPERVISOR)
set(KernelArch "x86" CACHE STRING "" FORCE)
set(KernelSel4Arch "x86_64" CACHE STRING "" FORCE)

# IMPORTANT: NO hypervisor support for bare-metal
set(KernelX86HypervisorSupport OFF CACHE BOOL "" FORCE)

# Disable huge pages - QEMU TCG mode doesn't support 1GB huge pages
set(KernelHugePage OFF CACHE BOOL "" FORCE)

# Disable PCID - QEMU TCG mode doesn't support PCID well
set(KernelSupportPCID OFF CACHE BOOL "" FORCE)

# Use generic micro-architecture for QEMU TCG compatibility
# generic avoids AVX instructions that TCG doesn't support
set(KernelX86MicroArch "generic" CACHE STRING "" FORCE)

set(KernelRootCNodeSizeBits 18 CACHE STRING "" FORCE)

# capDL settings
set(CapDLLoaderMaxObjects 90000 CACHE STRING "" FORCE)

# CAmkES Settings
set(CAmkESCPP ON CACHE BOOL "" FORCE)

# Platform configuration
correct_platform_strings()

find_package(seL4 REQUIRED)
sel4_configure_platform_settings()

ApplyData61ElfLoaderSettings(${KernelPlatform} ${KernelSel4Arch})

# Release settings
if(NOT DEFINED RELEASE)
    set(RELEASE OFF)
endif()
ApplyCommonReleaseVerificationSettings(${RELEASE} FALSE)

# Single node configuration
set(KernelMaxNumNodes 1 CACHE STRING "" FORCE)

# Include CAmkES helpers FIRST (needed by global-components)
find_package(camkes-tool REQUIRED)
camkes_tool_setup_camkes_build_environment()

# Find global components (after camkes-tool)
find_file(GLOBAL_COMPONENTS_PATH global-components.cmake
    PATHS ${project_dir}/global-components/
    CMAKE_FIND_ROOT_PATH_BOTH)
mark_as_advanced(FORCE GLOBAL_COMPONENTS_PATH)
if("${GLOBAL_COMPONENTS_PATH}" STREQUAL "GLOBAL_COMPONENTS_PATH-NOTFOUND")
    message(FATAL_ERROR "Failed to find global-components.cmake in ${project_dir}/global-components/")
endif()
include(${GLOBAL_COMPONENTS_PATH})

# Domain scheduling: 2 domains (data path + control plane)
# Domain 0: E1000Driver, TlsValidator, LwipProxy
# Domain 1: ControlPlane
set(KernelNumDomains 2 CACHE STRING "" FORCE)
set(KernelDomainSchedule "${CMAKE_CURRENT_LIST_DIR}/domain_schedule.c" CACHE FILEPATH "" FORCE)

# Default heap size for components
set(CAmkESDefaultHeapSize 4096 CACHE STRING "" FORCE)

# Enable lwIP library (for E1000Driver + ethdrivers)
set(LibLwip ON CACHE BOOL "" FORCE)
