# Copyright 2023 IBM All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A setuptools setup module for tls_test_tools"""

# Standard
import os

# Third Party
from setuptools import setup

# Read the README to provide the long description
python_base = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(python_base, "README.md"), "r") as handle:
    long_description = handle.read()

# Read version from the env
version = os.environ.get("RELEASE_VERSION")
assert version is not None, "Must set RELEASE_VERSION"

# Read in the requirements
with open(os.path.join(python_base, "requirements.txt"), "r") as handle:
    requirements = handle.read()

setup(
    name="tls_test_tools",
    version=version,
    description="A set of tools to quickly write unit tests for (m)TLS communication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/IBM/tls-test-tools",
    author="Gabe Goodhart",
    author_email="gabe.l.hart@gmail.com",
    license="APACHE",
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    packages=["tls_test_tools"],
    install_requires=requirements,
)
