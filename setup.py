#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OTPpy : setup data
# Copyright (C) 2021  BitLogiK


from setuptools import setup, find_packages
from otppy import VERSION


with open("README.md") as readme_file:
    readme = readme_file.read()


setup(
    name="OTPpy",
    version=VERSION,
    description="OTP library for Python 3",
    long_description=readme + "\n\n",
    long_description_content_type="text/markdown",
    keywords="otppy otp security hotp totp 2FA",
    author="BitLogiK",
    author_email="contact@bitlogik.fr",
    url="https://github.com/bitlogik/OTPpy",
    license="GPLv3",
    python_requires=">=3.4",
    install_requires=[],
    extras_require={"dev": ["black", "flake8", "pylint", "pytest"]},
    package_data={},
    include_package_data=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    zip_safe=False,
)
