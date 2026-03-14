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
assert_ptr = 0
assertion_time = 0


def authenticator_get_info():
    authenticator_info = {}
    authenticator_info[1] = ['FIDO_2_0', 'FIDO_2_1_PRE']
    authenticator_info[2] = ['credProtect']
    authenticator_info[3] = uuid.UUID(aaguid_str).bytes

    options = {}
    options['rk'] = True
    options['plat'] = False
    options['up'] = True
    options['uv'] = True

    authenticator_info[4] = options
    authenticator_info[5] = 1200
    authenticator_info[6] = [1]
    authenticator_info[7] = 8
    authenticator_info[8] = 128
    authenticator_info[9] = ['usb']
    authenticator_info[10] = [{'alg': -8, 'type': 'public-key'}]
    return authenticator_info, 0


def authenticator_make_credential(payload):
    client_data_hash = payload[1]
    rp = payload[2]
    user = payload[3]
    user_id = user['id']
    rpid = rp['id']

    if 5 in payload:
        exclude_list = payload[5]
        for exclude in exclude_list:
            if check_key_entity_exists(rpid, exclude):
                return '', 0x19

    rpid_hash = hash_data(rpid.encode())
    cred_id, pvtkey = gen_keys(rpid, user_id, user)

    flags = (0x45).to_bytes(1, 'big')
    sign_count = (4).to_bytes(4, 'big')

    aaguid = uuid.UUID(aaguid_str).bytes
    credential_id_length = (len(cred_id)).to_bytes(2, 'big')
    credential_public_key = to_cose_key(pvtkey)

    attested_credential_data = aaguid + credential_id_length + cred_id + credential_public_key
    auth_data = rpid_hash + flags + sign_count + attested_credential_data

    to_sign = auth_data + client_data_hash
    attstmt = {}
    attstmt['alg'] = get_algo()
    attstmt['sig'] = sign_challenge(pvtkey, to_sign)
    attstmt['x5c'] = [gen_certificate(pvtkey)]

    attestation_obj = {}
    attestation_obj[1] = 'packed'
    attestation_obj[2] = auth_data
    attestation_obj[3] = attstmt

    return attestation_obj, 0


def authenticator_get_assertion(payload):
    global signatures, assertion_time, assert_ptr

    signatures = []
    rpid = payload[1]
    client_data_hash = payload[2]
    allow_list = []

    if 3 in payload:
        allow_list = payload[3]

    rpid_hash = hash_data(rpid.encode())
    flags = (0x5).to_bytes(1, 'big')
    sign_count = (4).to_bytes(4, 'big')

    auth_data = rpid_hash + flags + sign_count
    to_sign = auth_data + client_data_hash

    if allow_list == []:
        all_keys = get_all_keys(rpid) or {}
        for key in all_keys:
            allow_list.append(all_keys[key]['publickeyentity'])
    else:
        filtered_allow_list = []
        for cred in allow_list:
            if check_key_entity_exists(rpid, cred):
                filtered_allow_list.append(cred)
        allow_list = filtered_allow_list

    number_of_credentials = len(allow_list)

    if number_of_credentials == 0:
        assert_ptr = 0
        assertion_time = 0
        return '', 0x2e

    c = 0
    for cred in allow_list:
        cred_id = cred['id']
        key = get_key(rpid, cred_id)
        if key is None:
            raise Exception('Key not found for rpid: ' + rpid + ' and credid: ' + cred_id.hex())

        pvtkey = key['pvtkey']
        sig = sign_challenge(pvtkey, to_sign)
        user = key['userentity']

        assert_obj = {}
        assert_obj[1] = cred
        assert_obj[2] = auth_data
        assert_obj[3] = sig
        assert_obj[4] = user
        if c == 0:
            assert_obj[5] = number_of_credentials
        c = c + 1
        signatures.append(assert_obj)

    assertion_time = int(time.time())
    assert_ptr = 1
    return signatures[0], 0


def authenticator_get_next_assertion():
    global signatures, assertion_time, assert_ptr

    if assert_ptr == 0 or assert_ptr > len(signatures) or int(time.time()) - assertion_time > 30:
        assert_ptr = 0
        signatures = []
        assertion_time = 0
        return '', 0x30

    assertion_time = int(time.time())
    sig = signatures[assert_ptr]
    assert_ptr = assert_ptr + 1
    return sig, 0


def authenticator_reset():
    global signatures, assertion_time, assert_ptr
    reset_keys()
    signatures = []
    assert_ptr = 0
    assertion_time = 0
    return '', 0
