"""Tests for OTPpy library."""


from datetime import datetime
from time import time
from otppy import OTP


def date_to_epoch(date_string):
    """Convert an ISO8601 string UTC date into the epoch integer."""
    given_date = datetime.strptime(date_string + "+0000", "%Y-%m-%d %H:%M:%S%z")
    return int(given_date.timestamp())


def test_otp_sanity():
    """Basic sanity check for OTP."""
    otp0 = OTP.fromb32("MFRGGZDFMZTWQ2LK")
    assert otp0.HOTP(2) == "816065"
    current_epoch = int(time())
    totp_computed = otp0.TOTP()[0]
    assert otp0.HOTP(current_epoch // 30) == totp_computed
    assert 30 - (current_epoch % 30) == otp0.remain_time(current_epoch)
    assert otp0.check_TOTP(otp0.TOTP()[0])


def test_hotp():
    """Test HOTP RFC4226."""

    seed_sha1 = b"12345678901234567890"
    otp1 = OTP(seed_sha1)

    # RFC4226 Dynamic Truncation Example 5.3
    hmac_result = bytes.fromhex("1f8698690e02ca16618550ef7f19da8e945b555a")
    assert otp1.truncate(hmac_result) == "872921"

    # RFC4226 Appendix D Test Values
    assert otp1.HOTP(0) == "755224"
    assert otp1.HOTP(1) == "287082"
    assert otp1.HOTP(2) == "359152"
    assert otp1.HOTP(3) == "969429"
    assert otp1.HOTP(4) == "338314"
    assert otp1.HOTP(5) == "254676"
    assert otp1.HOTP(6) == "287922"
    assert otp1.HOTP(7) == "162583"
    assert otp1.HOTP(8) == "399871"
    assert otp1.HOTP(9) == "520489"


def test_totp():
    """Test TOTP RFC6238."""

    # RFC6238 Appendix B Test Vectors

    seed_sha001 = b"12345678901234567890"
    seed_sha256 = seed_sha001 + b"123456789012"
    seed_sha512 = 3 * seed_sha001 + b"1234"
    otpsha1 = OTP(seed_sha001, digits=8)
    otp_256 = OTP(seed_sha256, "sha256", 8)
    otp_512 = OTP(seed_sha512, "sha512", 8)

    timecode1 = date_to_epoch("1970-01-01 00:00:59")
    assert otpsha1.epoch_otp(timecode1) == "94287082"
    assert otp_256.epoch_otp(timecode1) == "46119246"
    assert otp_512.epoch_otp(timecode1) == "90693936"

    timecode2 = date_to_epoch("2005-03-18 01:58:29")
    assert otpsha1.epoch_otp(timecode2) == "07081804"
    assert otp_256.epoch_otp(timecode2) == "68084774"
    assert otp_512.epoch_otp(timecode2) == "25091201"

    timecode3 = date_to_epoch("2005-03-18 01:58:31")
    assert otpsha1.epoch_otp(timecode3) == "14050471"
    assert otp_256.epoch_otp(timecode3) == "67062674"
    assert otp_512.epoch_otp(timecode3) == "99943326"

    timecode4 = date_to_epoch("2009-02-13 23:31:30")
    assert otpsha1.epoch_otp(timecode4) == "89005924"
    assert otp_256.epoch_otp(timecode4) == "91819424"
    assert otp_512.epoch_otp(timecode4) == "93441116"

    timecode5 = date_to_epoch("2033-05-18 03:33:20")
    assert otpsha1.epoch_otp(timecode5) == "69279037"
    assert otp_256.epoch_otp(timecode5) == "90698825"
    assert otp_512.epoch_otp(timecode5) == "38618901"

    timecode6 = date_to_epoch("2603-10-11 11:33:20")
    assert otpsha1.epoch_otp(timecode6) == "65353130"
    assert otp_256.epoch_otp(timecode6) == "77737706"
    assert otp_512.epoch_otp(timecode6) == "47863826"


def test_remtime():
    """Test the remaining time computation"""
    seed_sha1 = b"12345678901234567890"
    otpsha1 = OTP(seed_sha1)
    timecode1 = date_to_epoch("1970-01-01 00:00:59")
    assert otpsha1.remain_time(timecode1) == 1
    timecode2 = date_to_epoch("2005-03-18 01:58:29")
    assert otpsha1.remain_time(timecode2) == 1
    timecode3 = date_to_epoch("2005-03-18 01:58:31")
    assert otpsha1.remain_time(timecode3) == 29


def test_check():
    """Test the code checkings."""

    seed_sha001 = b"12345678901234567890"
    otpsha1 = OTP(seed_sha001, digits=8)
    timecode = date_to_epoch("2005-03-18 01:58:31")
    epoch = timecode // 30
    assert otpsha1.check_HOTP(epoch, "14150471") is False
    assert otpsha1.check_HOTP(epoch, "14050481") is False
    assert otpsha1.check_HOTP(epoch, "1405047A") is False
    assert otpsha1.check_HOTP(epoch, "1Z050471") is False
    assert otpsha1.check_HOTP(epoch, "140k0471") is False
    assert otpsha1.check_HOTP(epoch, "50471") is False
    assert otpsha1.check_HOTP(epoch, "050471") is False
    assert otpsha1.check_HOTP(epoch, "") is False
    assert otpsha1.check_HOTP(epoch, "1514050471") is False
    assert otpsha1.check_HOTP(epoch, "14050471 ") is False
    assert otpsha1.check_HOTP(epoch, " 14050471") is False
    assert otpsha1.check_HOTP(epoch, "14050471")
