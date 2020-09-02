import io
import base64
import sys
import struct
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import ecdsa
import Crypto
from hashlib import sha256
from ecdsa.numbertheory import inverse_mod
from ecdsa import SigningKey

curve = ecdsa.curves.NIST256p
key_len = 32
nsaddr = "127.0.0.1"

def get_record(dns_name, dns_rdatatype):
    # get DNSKEY for zone
    request = dns.message.make_query(dns_name,
                                     dns_rdatatype,
                                     want_dnssec=True)
    # send the query
    response = dns.query.udp(request,nsaddr)
    if response.rcode() != 0:
        # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
        pass
    answer = response.answer
    if answer[0].rdtype == dns.rdatatype.RRSIG:
        rrsig, rrset = answer
    elif answer[1].rdtype == dns.rdatatype.RRSIG:
        rrset, rrsig = answer
    else:
        raise BaseException('No signature set in record')
    return (rrset, rrsig)

def find_candidate_keys(keys, rrsig):
    candidate_keys = []
    value = keys.get(rrsig.signer)
    if value is None:
        return None
    if isinstance(value, dns.node.Node):
        try:
            rdataset = value.find_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        except KeyError:
            return None
    else:
        rdataset = value
    for rdata in rdataset:
        if rdata.algorithm == rrsig.algorithm and \
                dns.dnssec.key_id(rdata) == rrsig.key_tag:
            candidate_keys.append(rdata)
    return candidate_keys

def extract_pubkey(rrsigset, keys):
    for rrsig in rrsigset:
        for candidate_key in find_candidate_keys(keys, rrsig):
            keyptr = candidate_key.key
            x = Crypto.Util.number.bytes_to_long(keyptr[0:key_len])
            y = Crypto.Util.number.bytes_to_long(keyptr[key_len:key_len * 2])
            assert ecdsa.ecdsa.point_is_valid(curve.generator, x, y)
            point = ecdsa.ellipticcurve.Point(curve.curve, x, y, curve.order)
            verifying_key = ecdsa.keys.VerifyingKey.from_public_point(point, curve=curve).pubkey
            return verifying_key

def to_rdata(record, origin):
    s = io.BytesIO()
    record.to_wire(s, origin=origin)
    return s.getvalue()


def extract_signature(rrset, rrsigset, origin):
    hash_holder = sha256()
    s = io.BytesIO()
    for rrsig in rrsigset:
        rrname = rrset.name
        hash_holder.update(to_rdata(rrsig, origin=origin)[:18])
        hash_holder.update(rrsig.signer.to_digestable(origin))
        if rrsig.labels < len(rrname) - 1:
            suffix = rrname.split(rrsig.labels + 1)[1]
            rrname = dns.name.from_text('*', suffix)
        rrnamebuf = rrname.to_digestable(origin)
        rrfixed = struct.pack('!HHI', rrset.rdtype, rrset.rdclass,
                              rrsig.original_ttl)
        rrlist = sorted(rrset)
        for rr in rrlist:
            hash_holder.update(rrnamebuf)
            hash_holder.update(rrfixed)
            rrdata = rr.to_digestable(origin)
            rrlen = struct.pack('!H', len(rrdata))
            hash_holder.update(rrlen)
            hash_holder.update(rrdata)
        r = Crypto.Util.number.bytes_to_long(rrsig.signature[:key_len])
        s = Crypto.Util.number.bytes_to_long(rrsig.signature[key_len:])
        digest = int(hash_holder.hexdigest(), 16)
        return (r,s, digest)

def grab_pubkey(dns_name):
    name = dns.name.from_text(dns_name + '.')
    rrset, rrsig = get_record(dns_name, dns.rdatatype.DNSKEY)
    stream = io.BytesIO()
    rrset.to_wire(stream)
    stream.seek(0)
    hA = stream.getvalue()
    keys = {name:rrset}
    pubkey = extract_pubkey(rrsig, keys)
    return pubkey

def grab_signature(dns_name, record_type=dns.rdatatype.A):
    name = dns.name.from_text(dns_name + '.')
    rrset, rrsig = get_record(dns_name, record_type)
    stream = io.BytesIO()
    keys = {name:rrset}
    rA, sA, hA = extract_signature(rrset, rrsig, name)
    return (rA, sA, hA)

def crack(pubkey, rA, sA, hA, rB, sB, hB):
    n = pubkey.generator.order()
    # precalculate static values
    #z = hA - hB
    r_inv = inverse_mod(rA, n)

    for candidate in (sA - sB,
                      sA + sB,
                      -sA - sB,
                      -sA + sB):
        k = ((hA - hB) * inverse_mod(candidate, n)) % n
        d = (((sA * k - hA) % n) * r_inv) % n
        signingkey = SigningKey.from_secret_exponent(d, curve=curve)
        if signingkey.get_verifying_key().pubkey.verifies(hA, ecdsa.ecdsa.Signature(rA, sA)):
            print("works")
            signingkey = signingkey
            k = k
            priv_key = d
            print(priv_key)
