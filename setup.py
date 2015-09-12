# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

"""Installer and testing script for fanotify."""

from setuptools import setup
from setuptools.extension import Extension


EXT_MODULES = [
    Extension(
        'fanotify',
        sources=['fanotify.c'],
        ),
    ]

setup(
    name='fanotify',
    version='0.1',
    author='Mike Gerow',
    author_email='gerow@google.com',
    description=('Library to interface with linux fanotify features.'),
    license='Apache 2.0',
    test_suite='nose.collector',
    ext_modules=EXT_MODULES,
    )
