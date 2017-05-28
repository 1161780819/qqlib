# coding: utf-8

import os
import re
import json
import time
import tempfile
import requests




APPID = '549000912'

req = requests.session()

uri = {
    'login_sign'    : 'https://xui.ptlogin2.qq.com/cgi-bin/xlogin',
    'check'         : 'https://ssl.ptlogin2.qq.com/check',
    'cap_sess'      : 'https://ssl.captcha.qq.com/cap_union_new_gettype',
    'cap_sign'      : 'https://ssl.captcha.qq.com/cap_union_new_getsig',
    'cap_image'     : 'https://ssl.captcha.qq.com/cap_union_new_getcapbysig',
    'cap_verify'    : 'https://ssl.captcha.qq.com/cap_union_new_verify',
    'login'         : 'https://ssl.ptlogin2.qq.com/login',
    'qr'            : 'https://ssl.ptlogin2.qq.com/ptqrshow',
    'check_qr'      : 'https://ssl.ptlogin2.qq.com/ptqrlogin'

}

def get_login_sign():
    res = req.get(uri['login_sign'], params={
        'appid'   : APPID,
        's_url'   : 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone'
    })

    if res.status_code == 200:
        for c in res.cookies:
            if c.name == 'pt_login_sig':
                return {'err': 0, 'msg': 'ok', 'login_sign': c.value}
        return {'err': 1, 'msg': 'Failed to get login sign.', 'login_sign': None}
    else: 
        return {'err': 1, 'msg': res.text, 'login_sign': None}


def check(qq, sign):
    res = req.get(uri['check'], params={
        'pt_tea'        : 1,
        'pt_vcode'      : 1,
        'uin'           : qq,
        'appid'         : APPID,
        'js_type'       : 1,
        'login_sig'     : sign,
        'u1'            : 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone'
    })

    if res.status_code == 200:
        return {'err': 0, 'msg': 'ok', 'data': res.text}
    else:
        return {'err': 1, 'msg': res.text, 'data': None}

def get_capture(qq, code):
    # Get sess
    res = req.get(uri['cap_sess'], params={
        'uin'         : qq,
        'aid'         : APPID,
        'cap_cd'      : code
    })

    if res.status_code != 200:
        return {'err': 1, 'msg': res.text}
    
    sess = json.loads(res.text[1:-1])['sess']
    
    # Get sign
    res = req.get(uri['cap_sign'], params={
        'sess'      : sess,
        'aid'       : APPID,
        'uid'       : qq,
        'cap_cd'    : code
    })

    if res.status_code != 200:
        return {'err': 1, 'msg': res.text}

    sign = json.loads(res.text)['vsig']

    # Get capture
    res = req.get(uri['cap_image'], params={
        'sess'        : sess,
        'vsig'        : sign,
        'uid'         : qq,
        'cap_cd'      : code,
        'aid'         : APPID,
        'ischartype'  : 1
    })

    if res.status_code != 200:
        return {'err': 1, 'msg': res.text}

    tmp = tempfile.mkstemp(suffix = '.jpg')
    os.write(tmp[0], res.content)
    os.close(tmp[0])
    os.startfile(tmp[1])
    return {'err': 0, 'msg': 'ok', 
        'sess'    : sess,
        'sign'    : sign
    }


def verify_capture(qq, sess, code, sign, capture):
    res = req.post(uri['cap_verify'], data={
        'aid'       : APPID,
        'sess'      : sess,
        'uid'       : qq,
        'cap_cd'    : code,
        'vsig'      : sign,
        'ans'       : capture
    })

    if res.status_code != 200:
        return {'err': 1, 'msg': res.text}

    res = json.loads(res.text)
    if res['errorCode'] != '0':
        return {
            'err': 1, 
            'msg': bytes.fromhex(ascii(res['errMessage'])
                .replace(r'\x', '').replace('\'', '')).decode('utf-8')
        }
    else:
        return {'err': 0, 'msg': 'ok',
            'code': res['randstr'],
            'session': res['ticket']
        }



def login(qq, password, code, login_sign, session):

    res = req.get(uri['login'], params={
        'action'                : '5-3-1495966725481',
        'aid'                   : APPID,
        'daid'                  : 5,
        'from_ui'               : 1,
        'g'                     : 1,
        'h'                     : 1,
        'js_type'               : 1,
        'js_ver'                : 10220,
        'login_sig'             : login_sign,
        'p'                     : password,
        'pt_jstoken'            : 1419592444,
        'pt_randsalt'           : 2,
        'pt_uistyle'            : 40,
        'pt_vcode_v1'           : 1,
        'pt_verifysession_v1'   : session,
        'ptlang'                : 2052,
        'ptredirect'            : 0,
        't'                     : 1,
        'u'                     : qq,
        'u1'                    : 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone',
        'verifycode'            : code
    })
    return res.text

def get_qr():
    res = req.get(uri['qr'], params={
        'aid'   : APPID
    })

    tmp = tempfile.mkstemp(suffix = '.jpg')
    os.write(tmp[0], res.content)
    os.close(tmp[0])
    os.startfile(tmp[1])
    return check_qr()

def _hash(str):
    i = 0
    for x in str:
        i += (i << 5) + ord(x)
    return 2147483647 & i


def check_qr():
    cookies = req.cookies.get_dict()
    params={
        'login_sig' : cookies['pt_login_sig'],
        'aid'       : APPID,
        'ptqrtoken' : _hash(cookies['qrsig']),
        'action'    : '0-0-1495974089776',
        'ptredirect': 0,
        'js_ver'    : 10220,
        'js_type'   : 1,
        'g'         : 1,
        'h'         : 1,
        'from_ui'   : 1,
        't'         : 1,
        'pt_uistyle': 40,
        'daid'      : 5,
        'u1'        : 'https://qzs.qq.com/qzone/v5/loginsucc.html?para=izone'
    }
    while True:
        res = req.get(uri['check_qr'], params=params)
        matches = re.findall('\'(.*?)\'', res.text)
        if matches[0] == '66' or matches[0] == '67':
            pass
        else:
            return matches
        
        time.sleep(1)
