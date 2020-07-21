import Crypto
from Crypto.Util.number import inverse
import Crypto.PublicKey.ECC

import ecdsa
from ecdsa import SigningKey
from ecdsa.numbertheory import inverse_mod

import logging

logger = logging.getLogger(__name__)

def to_ecdsakey(secret_key, _from=ecdsa.SigningKey, _to=Crypto.PublicKey.ECC):
    # pointx, pointy, d
    return _to.import_key(secret_key.to_der())


class SignatureParameter(object):
    """
    DSA signature parameters.
    """

    def __init__(self, r, s):
        """

        :param r: Signature Param r
        :param s: Signature Param s
        """
        self.r = r
        self.s = s

    @property
    def tuple(self):
        """
        Signature parameter to tuple()
        :return: tuple(r,s)
        """
        return self.r, self.s


class RecoverableSignature(object):
    """
    A BaseClass for a recoverable EC/DSA Signature.
    """

    def __init__(self, sig, h, pubkey):
        """

        :param sig: tuple(long r, long s)
        :param h: bytestring message digest
        :param pubkey: pubkey object
        """
        self.sig = self._load_signature(sig)
        self.h = self._load_hash(h)
        self.pubkey = self._load_pubkey(pubkey)
        self.k = None
        self.x = None

    def __repr__(self):
        return "<%s 0x%x sig=%s public=%s private=%s >" % (self.__class__.__name__,
                                                           hash(self),
                                                           "(%s,%s)" % (
                                                               str(self.sig.r)[:10] + "…", str(self.sig.s)[:10] + "…"),
                                                           "✔" if self.pubkey else '⨯',
                                                           "✔" if self.x else '⨯')

    def _load_signature(self, sig):
        if all(hasattr(sig, att) for att in ('r','s')):
            return sig
        elif isinstance(sig, tuple):
            return SignatureParameter(*sig)

        raise ValueError("Invalid Signature Format! - Expected tuple(long r,long s) or SignatureParamter(long r, long s)")

    def _load_hash(self, h):
        if isinstance(h, (int, int)):
            return h
        elif isinstance(h, basestring):
            return Crypto.Util.number.bytes_to_long(h)

        raise ValueError("Invalid Hash Format! - Expected long(hash) or str(hash)")

    def _load_pubkey(self, pubkey):
        raise NotImplementedError("Must be implemented by subclass")



    def recover_nonce_reuse(self, other):
        """
        PrivateKey recovery from Signatures with reused nonce *k*.
        Note: a reused *k* results in the same value for *r* for both signatures
        :param other: other object of same type
        :return: self
        """
        raise NotImplementedError("%s cannot be called directly" % self.__class__.__name__)

    def export_key(self, *args, **kwargs):
        raise NotImplementedError("%s cannot be called directly" % self.__class__.__name__)

    def import_key(self, *args, **kwargs):
        raise NotImplementedError("%s cannot be called directly" % self.__class__.__name__)


class EcDsaSignature(RecoverableSignature):

    def __init__(self, sig, h, pubkey, curve=ecdsa.SECP256k1):
        self.curve = curve  # must be set before __init__ calls __load_pubkey

        super(EcDsaSignature, self).__init__(sig, h, pubkey)

        self.signingkey = None
        self.n = self.pubkey.generator.order()

        logger.debug("%r - check verifies.." % self)
        assert (self.pubkey.verifies(self.h, self.sig))
        logger.debug("%r - Signature is ok" % self)

    def _load_pubkey(self, pubkey):
        if isinstance(pubkey, ecdsa.ecdsa.Public_key):
            return pubkey
        elif isinstance(pubkey, basestring):
            return ecdsa.VerifyingKey.from_string(pubkey, curve=self.curve).pubkey
        return pubkey

    def export_key(self, *args, **kwargs):
        # format='PEM', pkcs8=None, passphrase=None, protection=None, randfunc=None
        ext_format = kwargs.get("format", "PEM")
        ext_format = "PEM"
        if ext_format == "PEM":
            return self.signingkey.to_pem()
        elif ext_format == "DER":
            return self.signingkey.to_der()
        raise ValueError("Unknown format '%s'" % ext_format)

    @staticmethod
    def import_key(encoded, passphrase=None):
        # encoded, passphrase=None
        # extern_key, passphrase=None
        # key = Cryptodome.PublicKey.ECC.import_key(*args, **kwargs)
        # return to_ecdsakey(key, _from=Cryptodome.PublicKey.ECC, _to=ecdsa.SigningKey)

        if encoded.startswith('-----'):
            return ecdsa.SigningKey.from_pem(encoded)

        # OpenSSH
        # if encoded.startswith(b('ecdsa-sha2-')):
        #    return _import_openssh(encoded)
        # DER
        if ord(encoded[0]) == 0x30:
            return ecdsa.SigningKey.from_der(encoded)
        raise Exception("Invalid Format")

    @property
    def privkey(self):
        """
        Reconstructs a DSA Signature Object
        :return: DSA Private Key Object
        """
        assert self.x  # privkey must be recovered fist
        assert self.signingkey
        return self.signingkey.privkey

    def recover_nonce_reuse(self, other):
        sig2 = other.sig  # rename it
        h2 = other.h  # rename it
        # precalculate static values
        z = self.h - h2
        r_inv = inverse_mod(self.sig.r, self.n)
        #
        # try all candidates
        #
        for candidate in (self.sig.s - sig2.s,
                          self.sig.s + sig2.s,
                          -self.sig.s - sig2.s,
                          -self.sig.s + sig2.s):
            k = (z * inverse_mod(candidate, self.n)) % self.n
            d = (((self.sig.s * k - self.h) % self.n) * r_inv) % self.n
            signingkey = SigningKey.from_secret_exponent(d, curve=self.curve)
            if signingkey.get_verifying_key().pubkey.verifies(self.h, self.sig):
                self.signingkey = signingkey
                self.k = k
                self.x = d
                return self
        assert False  # could not recover private key

curve = ecdsa.SECP256k1

# create standard ecdsa pubkey object from hex-encoded string
pub = ecdsa.VerifyingKey.from_string(bytes.fromhex(
        "a50eb66887d03fe186b608f477d99bc7631c56e64bb3af7dc97e71b917c5b3647954da3444d33b8d1f90a0d7168b2f158a2c96db46733286619fccaafbaca6bc"), curve=curve).pubkey
# create sampleA and sampleB recoverable signature objects.
# long r, long s, bytestr hash, pubkey obj.
sampleA = EcDsaSignature((3791300999159503489677918361931161866594575396347524089635269728181147153565,   #r
                          49278124892733989732191499899232294894006923837369646645433456321810805698952), #s
                         (
                             765305792208265383632692154455217324493836948492122104105982244897804317926),
                         pub)
sampleB = EcDsaSignature((3791300999159503489677918361931161866594575396347524089635269728181147153565,   #r
                          34219161137924321997544914393542829576622483871868414202725846673961120333282), #s'
                         (
                             23350593486085962838556474743103510803442242293209938584974526279226240784097),
                         pub)
# key not yet recovered
assert (sampleA.x is None)
# attempt to recover key - this updated object sampleA
sampleA.recover_nonce_reuse(sampleB)    # recover privatekey shared with sampleB
assert (sampleA.x is not None)          # assert privkey recovery succeeded. This gives us a ready to use ECDSA privkey object
#print(sampleA.export_key())
print(sampleA.privkey)
assert sampleA.privkey

