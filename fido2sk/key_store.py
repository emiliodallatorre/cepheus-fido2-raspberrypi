import os
import uuid

import cbor2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .crypto_ops import generate_cryptographic_keys

# Persistent encrypted key store path.
file_path = "/etc/fido2_security_key/keys.secret"
STORE_MAGIC = b"F2SK1"
STORE_AAD = b"fido2-security-key-store-v1"
KDF_SALT = b"fido2-security-key-device-kdf-v1"
KDF_ITERATIONS = 200_000
NONCE_SIZE = 12

current_keys = {}


def _read_hardware_identifier():
    # Prefer Raspberry Pi CPU serial, then machine-id, then MAC-derived node id.
    try:
        with open('/proc/cpuinfo', 'r', encoding='utf-8') as cpuinfo:
            for line in cpuinfo:
                if line.lower().startswith('serial'):
                    return line.split(':', 1)[1].strip().encode('utf-8')
    except Exception:
        pass

    try:
        with open('/etc/machine-id', 'r', encoding='utf-8') as machine_id:
            identifier = machine_id.read().strip()
            if identifier:
                return identifier.encode('utf-8')
    except Exception:
        pass

    return uuid.getnode().to_bytes(8, 'big')


def _derive_store_key():
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(_read_hardware_identifier())


def _encrypt_store(keys_dict):
    nonce = os.urandom(NONCE_SIZE)
    plaintext = cbor2.dumps(keys_dict)
    ciphertext = AESGCM(_derive_store_key()).encrypt(nonce, plaintext, STORE_AAD)
    return STORE_MAGIC + nonce + ciphertext


def _decrypt_store(blob):
    if len(blob) < len(STORE_MAGIC) + NONCE_SIZE + 16:
        raise ValueError("Encrypted key store is too short")
    nonce_start = len(STORE_MAGIC)
    nonce_end = nonce_start + NONCE_SIZE
    nonce = blob[nonce_start:nonce_end]
    ciphertext = blob[nonce_end:]
    plaintext = AESGCM(_derive_store_key()).decrypt(nonce, ciphertext, STORE_AAD)
    return cbor2.loads(plaintext)


def _save_keys_to_disk(keys_dict):
    directory = os.path.dirname(file_path)
    os.makedirs(directory, exist_ok=True)
    temp_path = file_path + '.tmp'
    payload = _encrypt_store(keys_dict)
    with open(temp_path, 'wb') as store_file:
        store_file.write(payload)
        store_file.flush()
        os.fsync(store_file.fileno())
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, file_path)


def _load_keys_from_disk():
    directory = os.path.dirname(file_path)
    os.makedirs(directory, exist_ok=True)

    if not os.path.exists(file_path):
        _save_keys_to_disk({})
        return {}

    with open(file_path, 'rb') as store_file:
        blob = store_file.read()

    if not blob:
        _save_keys_to_disk({})
        return {}

    if blob.startswith(STORE_MAGIC):
        return _decrypt_store(blob)

    # Legacy plaintext store migration.
    keys_dict = cbor2.loads(blob)
    _save_keys_to_disk(keys_dict)
    print('Migrated plaintext key store to encrypted format')
    return keys_dict


def initialize_store():
    global current_keys
    print("Reading crypto file")
    current_keys = _load_keys_from_disk()
    print('Keys loaded')


def gen_keys(rpid, userid, userentity):
    secret = str(uuid.uuid4())
    pvtkey, _ = generate_cryptographic_keys(secret)
    credid = uuid.uuid4().bytes + '_cryptane'.encode()

    if rpid in current_keys:
        current_rp = current_keys[rpid]
        for key in current_rp:
            cred = current_rp[key]
            if cred['userid'] == userid:
                credid = key

    key = {}
    key[credid] = {}
    key[credid]['pvtkey'] = pvtkey
    key[credid]['userid'] = userid
    key[credid]['userentity'] = userentity
    keyentity = {}
    keyentity['id'] = credid
    keyentity['type'] = 'public-key'
    key[credid]['publickeyentity'] = keyentity

    if rpid not in current_keys:
        current_keys[rpid] = {}

    current_keys[rpid].update(key)
    _save_keys_to_disk(current_keys)
    return credid, pvtkey


def reset_keys():
    global current_keys
    current_keys = {}
    _save_keys_to_disk(current_keys)


def check_key_exists(rpid, cred_id):
    return rpid in current_keys and cred_id in current_keys[rpid]


def check_key_entity_exists(rpid, entity):
    return check_key_exists(rpid, entity['id'])


def get_key(rpid, cred_id):
    if not check_key_exists(rpid, cred_id):
        return None
    return current_keys[rpid][cred_id]


def get_all_keys(rpid):
    if rpid in current_keys:
        return current_keys[rpid]
    return None


def get_cred_entity(rpid, cred_id):
    if not check_key_exists(rpid, cred_id):
        return None
    return current_keys[rpid][cred_id]['publickeyentity']
