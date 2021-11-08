"""OTPpy library"""

# OTPpy : core library
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


from time import time
from base64 import b32decode
from struct import pack, unpack

from .hmac_lib import hash_code


VERSION = "0.1.0"


class OTP:
    """OTP class"""

    def __init__(self, secret, hashalg="sha1", digits=6, time_window=30):
        if digits < 4 or digits > 8:
            raise ValueError("digits needs to be between 4 and 8.")
        self._secret = secret
        self.hashalg = hashalg
        self.digits = int(digits)
        self.time_window = int(time_window)

    # pylint: disable-next=invalid-name
    def HOTP(self, counter):
        """Compute counter OTP."""
        count_byts = pack(">Q", counter)
        hmac_digest = hash_code(self._secret, count_byts, self.hashalg)
        return self.truncate(hmac_digest)

    # pylint: disable-next=invalid-name
    def TOTP(self):
        """Compute cuurent time OTP."""
        present_time = int(time())
        code_string = self.epoch_otp(present_time)
        rema_sec = self.remain_time(present_time)
        return code_string, rema_sec

    # pylint: disable-next=invalid-name
    def check_HOTP(self, counter_value, hotp_string):
        """Check the validity of a HOTP code string"""
        computed_hotp = self.HOTP(counter_value)
        return hotp_string == computed_hotp

    # pylint: disable-next=invalid-name
    def check_TOTP(self, totp_string):
        """Check the validity of a TOTP code string"""
        return totp_string == self.TOTP()

    def epoch_otp(self, epoch_time):
        """Compute OTP from a given epoch integer."""
        return self.HOTP(epoch_time // self.time_window)

    def remain_time(self, time_code):
        """Compute the remaining time from the given time to the next window."""
        return ((time_code // self.time_window) + 1) * self.time_window - time_code

    def truncate(self, hmac_digest):
        """Dynamic Trucation from OTP standard. Gives number from hash."""
        read_shift = hmac_digest[-1] & 15
        token_base = (
            unpack(">I", hmac_digest[read_shift : read_shift + 4])[0] & 2147483647
        )
        token = token_base % 10 ** self.digits
        fmt = "{:0" + str(self.digits) + "d}"
        return fmt.format(token)

    @classmethod
    def fromb32(cls, secret_base32, hashalg="sha1", digits=6, time_window=30):
        """Load an OTP from parameters, including the share secret as base32 encoded."""
        b32_chars = len(secret_base32)
        pad_length = 8 - (b32_chars % 8)
        # case pad length = 8 is no padding (0 pad len)
        if pad_length not in [1, 3, 4, 6, 8]:
            raise ValueError("Bad base32 data length.")
        if pad_length < 8:
            secret_base32 += pad_length * "="
        secret = b32decode(secret_base32, True)
        return cls(secret, hashalg, digits, time_window)
