# coding: utf-8

import re
import rsa
import base64
import hashlib
import binascii

if __name__ == '__main__':
    from src import api, tea
else:
    from .src import api, tea

class QQ:
    def __init__(self, qq, password):
        self.qq = qq
        self.password = password

        # Get login sign
        results = api.get_login_sign()
        assert not results['err'], results['msg']

        self.login_sign = results['login_sign']

        # Check
        results = api.check(self.qq, self.login_sign)
        assert not results['err'], results['msg']

        matches = re.findall('\'(.*?)\'', results['data'])      
        
        self.salt       = matches[2].replace(r'\x', '')
        print(matches)
        if matches[0] == '1':
            # The captcha is required.
            self.mode = 1
            self.get_capture(matches[1]) 
        else:
            self.mode       = 0
            self.code       = matches[1]
            self.session    = matches[3]
            pass
        
        self.login()

    def get_capture(self, code):
        results = api.get_capture(self.qq, code)
        assert not results['err'], results['msg']
        capture = input('Please enter the verification code: ')
        
        results = api.verify_capture(self.qq, 
            results['sess'], code, results['sign'], capture)

        assert not results['err'], results['msg']

        self.code = results['code']
        self.session = results['session']

    def login(self):
        results = api.login(
            self.qq,
            self._encrpyt(),
            self.code,
            self.login_sign,
            self.session,
            self.mode
        )

        matches = re.findall('\'(.*?)\'', results)
        if matches[0] == '22009':
            return api.get_qr()
        else: 
            return matches

    def _encrpyt(self):
        # RSA: public key
        puk = rsa.PublicKey(int(
            'e9a815ab9d6e86abbf33a4ac64e9196d5be44a09bd0ed6ae052914e1a865ac83'
            '31fed863de8ea697e9a7f63329e5e23cda09c72570f46775b7e39ea9670086f8'
            '47d3c9c51963b131409b1e04265d9747419c635404ca651bbcbc87f99b8008f7'
            'f5824653e3658be4ba73e4480156b390bb73bc1f8b33578e7a4e12440e9396f2'
            '552c1aff1c92e797ebacdc37c109ab7bce2367a19c56a033ee04534723cc2558'
            'cb27368f5b9d32c04d12dbd86bbd68b1d99b7c349a8453ea75d1b2e94491ab30'
            'acf6c46a36a75b721b312bedf4e7aad21e54e9bcbcf8144c79b6e3c05eb4a154'
            '7750d224c0085d80e6da3907c3d945051c13c7c1dcefd6520ee8379c4f5231ed', 16
        ), 65537)
        
        a = bytes.fromhex(self.salt)
        b = hashlib.md5(self.password.encode())
        c = bytes.fromhex(b.hexdigest())
        d = hashlib.md5(c + a).hexdigest()
        e = binascii.b2a_hex(rsa.encrypt(c, puk)).decode()
        f = hex(len(e) // 2)[2:]
        g = binascii.hexlify(self.code.upper().encode()).decode()
        h = hex(len(g) // 2)[2:]
        i = '0' * (4 - len(f)) + f
        j = '0' * (4 - len(h)) + h
        k = '{}{}{}{}{}'.format(i, e, 
            binascii.hexlify(a).decode(), j, g)

        return base64.b64encode(tea.encrypt(
            bytes.fromhex(k), bytes.fromhex(d)
        )).decode().replace('/', '-').replace('+', '*').replace('=', '_')