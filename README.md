OTPpy
=====

OTP library for Python 3 : HOTP and TOTP ( RFC4226 &amp; RFC6238 )

Easy to use OTP 2FA check and generator, counter-based or time-based

* Fully compatible with standards
* Can manage 4 to 8 digits
* Can manage SHA1, SHA256 or SHA512 hash functions (as in RFC6238)

Compatible with Google Authenticator (default settings)

Example for generation :

    from otppy import OTP
    this_otp = OTP.fromb32("BASE32-SECRET-HERE")
    # TOTP return : [TOTP, Remaining Time in seconds]
    totp = this_otp.TOTP()
    print("TOTP Code :", totp[0])
    print(totp[1], "sec left")

Example for check :

    # Initialize
    from otppy import OTP
    this_otp = OTP.fromb32("BASE32-SECRET-HERE")
    # Check validity, return a boolean
    totp_valid = this_otp.TOTP(string_code_received)


## Using library

From pip/pypi repository :

    python3 pip install otppy

The old fashion way :  
Copy the otppy folder in your working directory.  
"from otppy import OTP" in your python program.

### Interface methods of OTPpy

`otppy.OTP( secret, hashalg="sha1", digits=6, time_window=30 )`  
Create an OTP object from a raw secret.  
Better to use with the class constructor "fromb32" :

`otppy.fromb32( secret_base32, hashalg="sha1", digits=6, time_window=30 )`  
Load an OTP from parameters, including the shared secret as base32 encoded.  
secret_base32 is the shared secret encoded in base32, optional padding.  
hashalg is the hash algorithm to use : "sha1", "sha256" or "sha512".  
digits is the integer for number of digits.  
time_window is the time width of a time block in seconds (integer).  
Note that secret_base32 is enough to use a standard OTP setting (sha1, 6 digits, 30 seconds blocks).

`.HOTP( counter )`  
Compute a HOTP code from the integer counter value.  
Return the HOTP code as a string.

`.TOTP( )`  
Compute a TOTP code from the current UTC machine time.  
Return a duet list : the TOTP code as a string, and the remaining validity time in seconds.

`.check_HOTP( counter_value, hotp_string )`  
Check the HOTP code string for the given values.  
Return a boolean.


`.check_TOTP( totp_string )`  
Check the TOTP code string (for the machine UTC time).  
Return a boolean.


Form more details: see otppy/ code.

### Internal tests

Test vectors from standards included in tests directory for pytest :

    python3 -m pytest tests


Licence :
----------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
