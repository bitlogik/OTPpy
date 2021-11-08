"""HMAC helper library"""

# OTPpy : hmac library
# Copyright (C) 2021  BitLogiK
# This file is part of OTPpy <https://github.com/bitlogik/otppy>.
#
# OTPpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OTPpy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OTPpy.  If not, see <http://www.gnu.org/licenses/>.


import hmac
import sys


def is_python_37():
    """Return boolean if current Python is at least version 3.7"""
    return sys.version_info.major == 3 and sys.version_info.minor >= 7


def hash_code(key, message, digest_alg):
    """Compute HMAC"""
    # digest_alg can be "sha1", "sha256" or "sha512"
    if digest_alg not in ["sha1", "sha256", "sha512"]:
        raise ValueError("Digest string must be sha1, sha256 or sha512.")
    if is_python_37():
        return hmac.digest(key, message, digest_alg)
    return hmac.HMAC(key, message, digest_alg).digest()
