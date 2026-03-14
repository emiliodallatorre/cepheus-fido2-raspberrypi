import time
import uuid

from .crypto_ops import (
    gen_certificate,
    get_algo,
    hash_data,
    sign_challenge,
    to_cose_key,
)
from .key_store import (
    check_key_entity_exists,
    gen_keys,
    get_all_keys,
    get_key,
    reset_keys,
)


aaguid_str = '4d41190c-7beb-4a84-8018-adf265a6352d'

signatures = []
assertptr = 0
assertiontime = 0


def authenticatorGetInfo():
    authenticatorInfo = {}
    authenticatorInfo[1] = ['FIDO_2_0', 'FIDO_2_1_PRE']
    authenticatorInfo[2] = ['credProtect']
    authenticatorInfo[3] = uuid.UUID(aaguid_str).bytes

    options = {}
    options['rk'] = True
    options['plat'] = False
    options['up'] = True
    options['uv'] = True

    authenticatorInfo[4] = options
    authenticatorInfo[5] = 1200
    authenticatorInfo[6] = [1]
    authenticatorInfo[7] = 8
    authenticatorInfo[8] = 128
    authenticatorInfo[9] = ['usb']
    authenticatorInfo[10] = [{'alg': -8, 'type': 'public-key'}]
    return authenticatorInfo, 0


def authenticatorMakeCredential(payload):
    clientDataHash = payload[1]
    rp = payload[2]
    user = payload[3]
    userid = user['id']
    rpid = rp['id']

    if 5 in payload:
        excludeList = payload[5]
        for exclude in excludeList:
            if check_key_entity_exists(rpid, exclude):
                return '', 0x19

    rpidhash = hash_data(rpid.encode())
    cred_id, pvtkey = gen_keys(rpid, userid, user)

    flags = (0x45).to_bytes(1, 'big')
    signCount = (4).to_bytes(4, 'big')

    aaguid = uuid.UUID(aaguid_str).bytes
    credentialIdLength = (len(cred_id)).to_bytes(2, 'big')
    credentialPublicKey = to_cose_key(pvtkey)

    attestedCredendialData = aaguid + credentialIdLength + cred_id + credentialPublicKey
    authData = rpidhash + flags + signCount + attestedCredendialData

    tosign = authData + clientDataHash
    attstmt = {}
    attstmt['alg'] = get_algo()
    attstmt['sig'] = sign_challenge(pvtkey, tosign)
    attstmt['x5c'] = [gen_certificate(pvtkey)]

    attestationobj = {}
    attestationobj[1] = 'packed'
    attestationobj[2] = authData
    attestationobj[3] = attstmt

    return attestationobj, 0


def authenticatorGetAssertion(payload):
    global signatures, assertiontime, assertptr

    signatures = []
    rpid = payload[1]
    clientDataHash = payload[2]
    allowList = []

    if 3 in payload:
        allowList = payload[3]

    rpidhash = hash_data(rpid.encode())
    flags = (0x5).to_bytes(1, 'big')
    signCount = (4).to_bytes(4, 'big')

    authdata = rpidhash + flags + signCount
    tosign = authdata + clientDataHash

    if allowList == []:
        all_keys = get_all_keys(rpid) or {}
        for key in all_keys:
            allowList.append(all_keys[key]['publickeyentity'])
    else:
        finlist = []
        for cred in allowList:
            if check_key_entity_exists(rpid, cred):
                finlist.append(cred)
        allowList = finlist

    numberOfCredentials = len(allowList)

    if numberOfCredentials == 0:
        assertptr = 0
        assertiontime = 0
        return '', 0x2e

    c = 0
    for cred in allowList:
        credid = cred['id']
        key = get_key(rpid, credid)
        pvtkey = key['pvtkey']
        sig = sign_challenge(pvtkey, tosign)
        user = key['userentity']

        assertobj = {}
        assertobj[1] = cred
        assertobj[2] = authdata
        assertobj[3] = sig
        assertobj[4] = user
        if c == 0:
            assertobj[5] = numberOfCredentials
        c = c + 1
        signatures.append(assertobj)

    assertiontime = int(time.time())
    assertptr = 1
    return signatures[0], 0


def authenticatorGetNextAssertion():
    global signatures, assertiontime, assertptr

    if assertptr == 0 or assertptr > len(signatures) or int(time.time()) - assertiontime > 30:
        assertptr = 0
        signatures = []
        assertiontime = 0
        return '', 0x30

    assertiontime = int(time.time())
    sig = signatures[assertptr]
    assertptr = assertptr + 1
    return sig, 0


def authenticatorReset():
    global signatures, assertiontime, assertptr
    reset_keys()
    signatures = []
    assertptr = 0
    assertiontime = 0
    return '', 0
