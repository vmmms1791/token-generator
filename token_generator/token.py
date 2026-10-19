import datetime
from asn1crypto import core, keys, algos
import os

class DynamicToken:
    OID = '1.3.6.1.4.1.19912.1.2'
    PREFIX = 'PO-CGQ14.05.'

    def __init__(self, device_key: bytes, n_code: str = None, device_id: str = None):
        """
        device_key – PEM encoded private key (EC or RSA).
        n_code, device_id – informational, not encoded in token.
        """
        if isinstance(device_key, bytes):
            self.device_key = keys.PrivateKey.load(device_key)
        else:
            self.device_key = device_key
        self.n_code = n_code
        self.device_id = device_id

    def _build_inner_sequence(self, timestamp: int = None) -> core.Sequence:
        if timestamp is None:
            timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        utf8_str = f'{self.PREFIX}{timestamp}'
        return core.Sequence([
            core.ObjectIdentifier(self.OID),
            core.UTF8String(utf8_str),
            core.Integer(1),
            core.Integer(0),
        ])

    def _wrap_application(self, data: bytes, tag: int) -> bytes:
        # Encode tag as multi-byte if needed (tag >= 31)
        tag_bytes = []
        if tag < 0x1F:
            tag_bytes.append(tag)
        else:
            # encode tag number in base 128 with continuation bit
            # First byte: class=APPLICATION (0x40), constructed=0x20, escape tag number 0x1F
            first = 0x40 | 0x20 | 0x1F  # 0x7F
            tag_bytes.append(first)
            # Encode tag number
            tmp = tag
            while True:
                byte = tmp & 0x7F
                tmp >>= 7
                if tmp:
                    tag_bytes.append(byte | 0x80)  # continuation bit set
                else:
                    tag_bytes.append(byte)
                    break
        # Length: assume short form (<128)
        if len(data) < 128:
            length_bytes = bytes([len(data)])
        else:
            raise ValueError('Data exceeds 127 bytes; long form not implemented')
        return bytes(tag_bytes) + length_bytes + data

    def build_token(self, timestamp: int = None) -> bytes:
        """Generate token with a placeholder signature.
        Replace _sign_inner with real signature using self.device_key.
        """
        inner_seq = self._build_inner_sequence(timestamp)
        inner_der = inner_seq.dump()
        # To add a BIT STRING signature we need to construct a new SEQUENCE:
        # OID, UTF8String, INTEGER(1), INTEGER(0), BIT_STRING(signature)
        # We'll rebuild with signature.
        if timestamp is None:
            timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        utf8_str = f'{self.PREFIX}{timestamp}'
        # Placeholder signature: 64 zero bytes (replace with real signature)
        signature = b'\x00' * 64
        bitstring = core.BitString(signature)
        signed_seq = core.Sequence([
            core.ObjectIdentifier(self.OID),
            core.UTF8String(utf8_str),
            core.Integer(1),
            core.Integer(0),
            bitstring,
        ])
        inner_der = signed_seq.dump()
        inner_app = self._wrap_application(inner_der, 0x33)  # APPLICATION 33 as per token
        outer_app = self._wrap_application(inner_app, 0x33)  # outer also APPLICATION 33
        return outer_app

    @staticmethod
    def parse_token(token_hex: str) -> dict:
        from binascii import unhexlify
        from asn1crypto import core
        data = unhexlify(token_hex)

        def parse_tlv(buf, offset=0):
            # tag
            first = buf[offset]; offset+=1
            class_bits = first & 0xC0
            constructed_bit = first & 0x20
            tag_number = first & 0x1F
            if tag_number == 0x1F:
                tag_number = 0
                while True:
                    if offset >= len(buf):
                        raise ValueError('Tag length out of bounds')
                    b = buf[offset]; offset+=1
                    tag_number = (tag_number << 7) | (b & 0x7F)
                    if not (b & 0x80):
                        break
            # length
            length_byte = buf[offset]; offset+=1
            if length_byte & 0x80:
                num_len = length_byte & 0x7F
                length = 0
                for _ in range(num_len):
                    if offset >= len(buf):
                        raise ValueError('Length indefinite')
                    length = (length << 8) | buf[offset]; offset+=1
            else:
                length = length_byte
            value = buf[offset:offset+length]; offset+=length
            return tag_number, class_bits|constructed_bit, length, value, offset

        # Strip outer two layers of APPLICATION 33
        outer_tag_number, outer_tag_enc, outer_len, outer_val, _ = parse_tlv(data)
        # outer_tag_number should be 33 (APPLICATION 33)
        inner_tag_number, inner_tag_enc, inner_len, inner_val, _ = parse_tlv(outer_val)
        # inner_tag_number should be 33 as well
        # Now inner_val should contain a sequence of elements: OID, UTF8String, INTEGER(1), INTEGER(0), BIT_STRING
        seq_offset = 0
        results = {}
        while seq_offset < len(inner_val):
            t_number, t_enc, length, value, seq_offset = parse_tlv(inner_val, seq_offset)
            if t_number == 6:  # OID (universal)
                # Need to reconstruct TLV for load
                oid_tlv = bytes([0x06, length]) + value
                results['oid'] = core.ObjectIdentifier.load(oid_tlv).native
            elif t_number == 0x0C:  # UTF8String (universal 12)
                utf8_tlv = bytes([0x0C, length]) + value
                results['utf8'] = core.UTF8String.load(utf8_tlv).native
            elif t_number == 0x02:  # INTEGER (universal)
                int_tlv = bytes([0x02, length]) + value
                if 'int1' not in results:
                    results['int1'] = core.Integer.load(int_tlv).native
                else:
                    results['int2'] = core.Integer.load(int_tlv).native
            elif t_number == 0x03:  # BIT STRING (universal)
                bitstring_tlv = bytes([0x03, length]) + value
                results['bitstring'] = core.BitString.load(bitstring_tlv).native
            else:
                # Could be application-tagged UTF8String etc.; try to extract string if it looks like ASCII
                # For simplicity, ignore; but we can attempt to decode as UTF-8 if printable
                pass
        return results

    def sign_inner(self, inner_der: bytes) -> bytes:
        """Sign inner DER with device private key.
        Must be implemented based on key type.
        """
        # Example for RSA PKCS#1 v1.5 using SHA256
        if isinstance(self.device_key, keys.RSAPrivateKey):
            signer = algos.SignatureAlgorithm('rsassa_pkcs1v15', 'sha256')
            return signer.sign(self.device_key, inner_der)
        elif isinstance(self.device_key, keys.ECDSAPrivateKey):
            signer = algos.SignatureAlgorithm('ecdsa', 'sha256')
            return signer.sign(self.device_key, inner_der)
        else:
            raise NotImplementedError('Signing not implemented for key type')