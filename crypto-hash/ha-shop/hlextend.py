# Copyright (C) 2014 by Stephen Bradshaw
#
# SHA1 and SHA2 generation routines from SlowSha https://code.google.com/p/slowsha/
# which is: Copyright (C) 2011 by Stefano Palazzo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
 Pure Python Hash Length Extension module.

 Currently supports SHA1, SHA256 and SHA512, more algorithms will
 be added in the future.


 Create a hash by calling one of the named constuctor functions:
 sha1(), sha256(), and sha512(), or by calling new(algorithm).

 The hash objects have the following methods:

 hash(message):

     Feeds data into the hash function using the normal interface.

 extend(appendData, knownData, secretLength, startHash):

     Performs a hash length extension attack.  Returns the bytestring to
     use when appending data.

 hexdigest():

     Returns a hexlified version of the hash output.


 Assume you have a hash generated from an unknown secret value concatenated with
 a known value, and you want to be able to produce a valid hash after appending
 additional data to the known value.

 If the hash algorithm used is one of the vulnerable functions implemented in
 this module, is is possible to achieve this without knowing the secret value
 as long as you know (or can guess, perhaps by brute force) the length of that
 secret value.  This is called a hash length extension attack.

 Given an existing sha1 hash value '52e98441017043eee154a6d1af98c5e0efab055c',
 known data of 'hello', an unknown secret of length 10 and data you wish
 to append of 'file', you would do the following to perform the attack:

 >>> import hlextend
 >>> sha = hlextend.new('sha1')
 >>> print sha.extend(b'file', b'hello', 10, '52e98441017043eee154a6d1af98c5e0efab055c')
 b'hello\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xfile'
 >>> print sha.hexdigest()
 c60fa7de0860d4048a3bfb36b70299a95e6587c9

The unknown secret (of length 10), that when hashed appended with 'hello' produces
a SHA1 hash of '52e98441017043eee154a6d1af98c5e0efab055c', will then produce
a SHA1 hash of 'c60fa7de0860d4048a3bfb36b70299a95e6587c9' when appended with the output
from the extend function above.

If you are not sure of the exact length of the secret value, simply try the above
multiple times specifying different values for the length to brute force.
"""


from re import match
from math import ceil
from typing import Union


__version__ = "0.2"


class Hash(object):
    """Parent class for hash functions"""

    def hash(self, message):
        """Normal input for data into hash function"""

        length = bin(len(message) * 8)[2:].rjust(self._blockSize, "0")

        while len(message) > self._blockSize:
            self._transform(
                "".join([bin(a)[2:].rjust(8, "0") for a in message[: self._blockSize]])
            )
            message = message[self._blockSize :]

        message = self.__hashBinaryPad(message, length)

        for a in range(len(message) // self._b2):
            self._transform(message[a * self._b2 : a * self._b2 + self._b2])

    def extend(self, appendData, knownData, secretLength, startHash):
        """Hash length extension input for data into hash function"""
        self.__checkInput(secretLength, startHash)
        self.__setStartingHash(startHash)

        extendLength = self.__hashGetExtendLength(secretLength, knownData, appendData)

        message = appendData

        while len(message) > self._blockSize:
            self._transform(
                "".join([bin(a)[2:].rjust(8, "0") for a in message[: self._blockSize]])
            )
            message = message[self._blockSize :]

        message = self.__hashBinaryPad(message, extendLength)

        for i in range(len(message) // self._b2):
            self._transform(message[i * self._b2 : i * self._b2 + self._b2])

        return self.__hashGetPadData(secretLength, knownData, appendData)

    def hexdigest(self):
        """Outputs hash data in hexlified format"""
        return "".join([(("%0" + str(self._b1) + "x") % (a)) for a in self.__digest()])

    def __init__(self):
        # pre calculate some values that get used a lot
        self._b1 = self._blockSize / 8
        self._b2 = self._blockSize * 8

    def __digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match("^_h\d+$", a)]

    def __setStartingHash(self, startHash):
        c = 0
        hashVals = [
            int(startHash[a : a + int(self._b1)], base=16)
            for a in range(0, len(startHash), int(self._b1))
        ]
        for hv in [a for a in dir(self) if match("^_h\d+$", a)]:
            self.__setattr__(hv, hashVals[c])
            c += 1

    def __checkInput(self, secretLength, startHash):
        if not isinstance(secretLength, int):
            raise TypeError("secretLength must be a valid integer")
        if secretLength < 1:
            raise ValueError("secretLength must be grater than 0")
        if not match("^[a-fA-F0-9]{" + str(len(self.hexdigest())) + "}$", startHash):
            raise ValueError(
                "startHash must be a string of length "
                + str(len(self.hexdigest()))
                + " in hexlified format"
            )

    def __byter(self, byteVal):
        """Helper function to return usable values for hash extension append data"""
        if byteVal < 0x20 or byteVal > 0x7E:
            return "\\x%02x" % (byteVal)
        else:
            return chr(byteVal)

    def __binToByte(self, binary) -> bytearray:
        return int(binary, 2).to_bytes(len(binary) // 8, byteorder="big")

    def __hashGetExtendLength(self, secretLength, knownData, appendData):
        """Length function for hash length extension attacks"""
        # binary length (secretLength + len(knownData) + size of binarysize+1) rounded to a multiple of blockSize + length of appended data
        originalHashLength = int(
            ceil(
                (secretLength + len(knownData) + self._b1 + 1) / float(self._blockSize)
            )
            * self._blockSize
        )
        newHashLength = originalHashLength + len(appendData)
        return bin(newHashLength * 8)[2:].rjust(self._blockSize, "0")

    def __hashGetPadData(self, secretLength, knownData, appendData):
        """Return append value for hash extension attack"""
        originalHashLength = bin((secretLength + len(knownData)) * 8)[2:].rjust(
            self._blockSize, "0"
        )
        padData = "".join(bin(i)[2:].rjust(8, "0") for i in knownData) + "1"
        padData += (
            "0"
            * (
                ((self._blockSize * 7) - (len(padData) + (secretLength * 8)) % self._b2)
                % self._b2
            )
            + originalHashLength
        )

        return self.__binToByte(padData) + appendData

    def __hashBinaryPad(self, message, length):
        """Pads the final blockSize block with \x80, zeros, and the length, converts to binary"""
        out_msg = ""

        for i in message:
            out_msg += bin(i)[2:].rjust(8, "0")

        out_msg += "1"
        out_msg += (
            "0" * (((self._blockSize * 7) - len(out_msg) % self._b2) % self._b2)
            + length
        )

        return out_msg


class SHA1(Hash):

    (
        _h0,
        _h1,
        _h2,
        _h3,
        _h4,
    ) = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )
    _blockSize = 64

    def _transform(self, chunk):

        def lrot(x, n):
            return (x << n) | (x >> (32 - n))

        w = []

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32 : j * 32 + 32], 2))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1) & 0xFFFFFFFF)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5A827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8F1BBCDC
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xCA62C1D6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xFFFFFFFF
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xFFFFFFFF
        self._h1 = (self._h1 + b) & 0xFFFFFFFF
        self._h2 = (self._h2 + c) & 0xFFFFFFFF
        self._h3 = (self._h3 + d) & 0xFFFFFFFF
        self._h4 = (self._h4 + e) & 0xFFFFFFFF


class SHA256(Hash):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    )

    _blockSize = 64

    def _transform(self, chunk):
        def rrot(x, n):
            return (x >> n) | (x << (32 - n))

        w = []

        k = [
            0x428A2F98,
            0x71374491,
            0xB5C0FBCF,
            0xE9B5DBA5,
            0x3956C25B,
            0x59F111F1,
            0x923F82A4,
            0xAB1C5ED5,
            0xD807AA98,
            0x12835B01,
            0x243185BE,
            0x550C7DC3,
            0x72BE5D74,
            0x80DEB1FE,
            0x9BDC06A7,
            0xC19BF174,
            0xE49B69C1,
            0xEFBE4786,
            0x0FC19DC6,
            0x240CA1CC,
            0x2DE92C6F,
            0x4A7484AA,
            0x5CB0A9DC,
            0x76F988DA,
            0x983E5152,
            0xA831C66D,
            0xB00327C8,
            0xBF597FC7,
            0xC6E00BF3,
            0xD5A79147,
            0x06CA6351,
            0x14292967,
            0x27B70A85,
            0x2E1B2138,
            0x4D2C6DFC,
            0x53380D13,
            0x650A7354,
            0x766A0ABB,
            0x81C2C92E,
            0x92722C85,
            0xA2BFE8A1,
            0xA81A664B,
            0xC24B8B70,
            0xC76C51A3,
            0xD192E819,
            0xD6990624,
            0xF40E3585,
            0x106AA070,
            0x19A4C116,
            0x1E376C08,
            0x2748774C,
            0x34B0BCB5,
            0x391C0CB3,
            0x4ED8AA4A,
            0x5B9CCA4F,
            0x682E6FF3,
            0x748F82EE,
            0x78A5636F,
            0x84C87814,
            0x8CC70208,
            0x90BEFFFA,
            0xA4506CEB,
            0xBEF9A3F7,
            0xC67178F2,
        ]

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32 : j * 32 + 32], 2))

        for i in range(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self._h0 = (self._h0 + a) & 0xFFFFFFFF
        self._h1 = (self._h1 + b) & 0xFFFFFFFF
        self._h2 = (self._h2 + c) & 0xFFFFFFFF
        self._h3 = (self._h3 + d) & 0xFFFFFFFF
        self._h4 = (self._h4 + e) & 0xFFFFFFFF
        self._h5 = (self._h5 + f) & 0xFFFFFFFF
        self._h6 = (self._h6 + g) & 0xFFFFFFFF
        self._h7 = (self._h7 + h) & 0xFFFFFFFF


class SHA512(Hash):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    )

    _blockSize = 128

    def _transform(self, chunk):

        def rrot(x, n):
            return (x >> n) | (x << (64 - n))

        w = []

        k = [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ]

        for j in range(len(chunk) // 64):
            w.append(int(chunk[j * 64 : j * 64 + 64], 2))

        for i in range(16, 80):
            s0 = rrot(w[i - 15], 1) ^ rrot(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = rrot(w[i - 2], 19) ^ rrot(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(80):
            s0 = rrot(a, 28) ^ rrot(a, 34) ^ rrot(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 14) ^ rrot(e, 18) ^ rrot(e, 41)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF

        self._h0 = (self._h0 + a) & 0xFFFFFFFFFFFFFFFF
        self._h1 = (self._h1 + b) & 0xFFFFFFFFFFFFFFFF
        self._h2 = (self._h2 + c) & 0xFFFFFFFFFFFFFFFF
        self._h3 = (self._h3 + d) & 0xFFFFFFFFFFFFFFFF
        self._h4 = (self._h4 + e) & 0xFFFFFFFFFFFFFFFF
        self._h5 = (self._h5 + f) & 0xFFFFFFFFFFFFFFFF
        self._h6 = (self._h6 + g) & 0xFFFFFFFFFFFFFFFF
        self._h7 = (self._h7 + h) & 0xFFFFFFFFFFFFFFFF


def new(algorithm) -> Union[SHA1, SHA256, SHA512]:
    obj = {
        "sha1": SHA1,
        "sha256": SHA256,
        "sha512": SHA512,
    }[algorithm]()
    return obj


def sha1():
    """Returns a new sha1 hash object"""
    return new("sha1")


def sha256():
    """Returns a new sha256 hash object"""
    return new(
        "sha256",
    )


def sha512():
    """Returns a new sha512 hash object"""
    return new(
        "sha512",
    )


__all__ = ("sha1", "sha256", "sha512")
