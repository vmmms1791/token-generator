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
        tag_byte = 0x60 | tag  # APPLICATION class (0x40) + constructed (0x20)
        if len(data) < 128:
            length_bytes = bytes([len(data)])
        else:
            # For simplicity, we assume data <128 bytes in our usage.
            raise ValueError('Data exceeds 127 bytes; long form not implemented')
        return bytes([tag_byte]) + length_bytes + data

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
        inner_app = self._wrap_application(inner_der, 0x30)
        outer_app = self._wrap_application(inner_app, 0x31)
        return outer_app

    @staticmethod
    def parse_token(token_hex: str) -> dict:
        from binascii import unhexlify
        data = unhexlify(token_hex)

        def parse_tlv(buf, offset=0):
            if offset >= len(buf):
                return None, None, None, offset
            tag = buf[offset]; offset += 1
            length_byte = buf[offset]; offset += 1
            if length_byte & 0x80:
                n = length_byte & 0x7F
                length = 0
                for _ in range(n):
                    length = (length << 8) | buf[offset]; offset += 1
            else:
                length = length_byte
            value = buf[offset:offset + length]; offset += length
            return tag, length, value, offset

        outer_tag, outer_len, outer_val, _ = parse_tlv(data)
        inner_tag, inner_len, inner_val, _ = parse_tlv(outer_val)
        # inner_val should be SEQUENCE
        seq_offset = 0
        results = {}
        while seq_offset < len(inner_val):
            tag, length, value, seq_offset = parse_tlv(inner_val, seq_offset)
            if tag == 0x06:  # OID
                results['oid'] = core.ObjectIdentifier.load(value).native
            elif tag == 0x0C:  # UTF8String
                results['utf8'] = core.UTF8String.load(value).native
            elif tag == 0x02:  # INTEGER
                if 'int1' not in results:
                    results['int1'] = core.Integer.load(value).native
                else:
                    results['int2'] = core.Integer.load(value).native
            elif tag == 0x03:  # BIT STRING
                results['bitstring'] = core.BitString.load(value).native
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

if __name__ == '__main__':
    # Simple self‑test
    import tempfile
    from asn1crypto.keys import PrivateKey
    # Generate a temporary EC key for demo
    key = PrivateKey.generate('ec', 'secp256r1')
    key_pem = key.dump()
    token = DynamicToken(device_key=key_pem, n_code='TEST', device_id='001')
    tok = token.build_token()
    print('Generated token hex:', tok.hex())
    parsed = DynamicToken.parse_token(tok.hex())
    print('Parsed:', parsed)
