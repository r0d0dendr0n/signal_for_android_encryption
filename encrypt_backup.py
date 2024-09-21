import struct
import sqlite3
import json
import sys
import secrets
import os
from pathlib import Path
from enum import Enum
from io import BytesIO
from typing import NamedTuple, BinaryIO, Iterator, Union, Dict, cast
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import  Hash, SHA256, SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import Backups_pb2

DefaultBackend = default_backend()

class MACMismatchError(Exception):
    pass

class UnsupportedVersionError(ValueError):

def increment_initialisation_vector(initialisation_vector: bytes) -> bytes:
    counter = struct.unpack(">I", initialisation_vector[:4])[0]
    counter = (counter + 1) & 0xFFFFFFFF
    return struct.pack(">I", counter) + initialisation_vector[4:]

class Keys(NamedTuple):
    cipher_key: bytes
    hmac_key: bytes

class AttachmentType(Enum):
    ATTACHMENT=0,
    AVATAR=1,
    STICKER=2

# Probably done
def encrypt_backup_frame(input_data: bytes, hmac_key: bytes, cipher_key: bytes, iv: bytes, version: int) -> bytes:
    """Encrypts and generates an encrypted frame."""
    hmac = HMAC(hmac_key, SHA256(), backend=DefaultBackend)
    cipher = Cipher(
        algorithm=AES(cipher_key),
        mode=CTR(iv),
        backend=DefaultBackend
    )
    encryptor = cipher.encryptor()

    output_data = bytes()
    data_length = len(input_data)+10 #mac suffix

    if(version is None):
        if data_length>0:
            output_data = struct.pack(">I", data_length)
    elif(version == 1):
        if data_length>0:
            unencrypted_length_bytes = struct.pack(">I", data_length)
            encrypted_length_bytes = encryptor.update(unencrypted_length_bytes)
            #print("encrypted_length_bytes: {}".format(encrypted_length_bytes))
            #print("hmac.update(encrypted_length={})".format(encrypted_length_bytes))
            hmac.update(encrypted_length_bytes)
            output_data = encrypted_length_bytes
    else:
        raise UnsupportedVersionError(header_version)

    # print("Encrypting frame {} bytes long".format(data_length))
    #print("{}".format(input_data[0:32]))
    #print("{}".format(input_data[-32:]))

    ciphertext = encryptor.update(input_data) + encryptor.finalize()

    hmac.update(ciphertext)
    mac = hmac.finalize()[:10]
    #print("mac: {}".format(mac))

    output_data += ciphertext + mac
    
    return output_data

def encrypt_frame_payload(backup_file: BinaryIO, raw_payload: bytes, hmac_key: bytes, cipher_key: bytes, iv: bytes, chunk_size: int = 8 * 1024,) -> bytes:
    """Encrypts and generates an encrypted payload."""
    hmac = HMAC(hmac_key, SHA256(), backend=DefaultBackend)
    hmac.update(iv)
    # print("iv: {}".format(iv))

    cipher = Cipher(
        algorithm=AES(cipher_key),
        mode=CTR(iv),
        backend=DefaultBackend
    )
    encryptor = cipher.encryptor()

    length = len(raw_payload)
    payload_reader = BytesIO(raw_payload)
    ciphertext = bytes()
    # Read the data, incrementally decrypting one chunk at a time
    while length > 0:
        this_chunk_length = min(chunk_size, length)
        length -= this_chunk_length
        cleartext = payload_reader.read(this_chunk_length)

        encrypted_chunk = encryptor.update(cleartext)
        hmac.update(encrypted_chunk)
        ciphertext += encrypted_chunk

    mac = hmac.finalize()[:10]

    ciphertext += encryptor.finalize()

    return ciphertext + mac

def getAttachmentObj(attachment_data: bytes, att_file: BinaryIO, attachType: AttachmentType):
    if(attachType == AttachmentType.ATTACHMENT):
        attachmentMsg = Backups_pb2.BackupFrame()
        attachmentMsg.attachment.rowId = int(os.path.splitext(os.path.basename(att_file.name))[0])
        attachmentMsg.attachment.attachmentId = attachmentMsg.attachment.rowId
        attachmentMsg.attachment.length = len(attachment_data)
        return attachmentMsg
    elif(attachType == AttachmentType.AVATAR):
        avatarMsg = Backups_pb2.BackupFrame()
        avatarMsg.avatar.recipientId = os.path.splitext(os.path.basename(att_file.name))[0]
        avatarMsg.avatar.name = avatarMsg.avatar.recipientId
        avatarMsg.avatar.length = len(attachment_data)
        return avatarMsg
    elif(attachType == AttachmentType.STICKER):
        stickerMsg = Backups_pb2.BackupFrame()
        stickerMsg.sticker.rowId = int(os.path.splitext(os.path.basename(att_file.name))[0])
        stickerMsg.sticker.length = len(attachment_data)
        return stickerMsg
    else:
        print("Unknown type!")
        sys.exit()

def writeAttachmentObj(backup_file: BinaryIO, keys: Keys, iv: bytes, input_directory: str, subdir: str, attachType: AttachmentType, version: int):
    attachments_dir = Path(input_directory + "/" + subdir)
    for attachment_file in attachments_dir.iterdir():
        with open(attachment_file, "rb") as att_file:
            attachment_data = att_file.read()
            attachmentMsg = getAttachmentObj(attachment_data, att_file, attachType)

            serializedMsg = attachmentMsg.SerializeToString()
            encrypted_att = encrypt_backup_frame(serializedMsg, keys.hmac_key, keys.cipher_key, iv, version)
            iv = increment_initialisation_vector(iv)
            backup_file.write(encrypted_att)

            encrypted_payload = encrypt_frame_payload(backup_file, attachment_data, keys.hmac_key, keys.cipher_key, iv)
            iv = increment_initialisation_vector(iv)
            backup_file.write(encrypted_payload)

            print("Frame bytes: {}, payload bytes: {}".format(len(serializedMsg), len(attachment_data)))
    
    return iv

def create_backup_file(backup_file: BinaryIO, passphrase: str, input_directory: Path):
    """Create an encrypted Signal backup file."""
    #salt = b"\x00" * 32  # Example, you should generate a random salt
    #iv = b"\x00" * 16  # Example, you should generate a random IV
    salt = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    iv = b'\x0fn6N:\xe5\xa6\x9bN\xf5\xdf\xceL\xfb\x95:'
    salt = b'\x8di3\'\xa9K\xb5\xa4\x94\x11S\xd3"\xaaw\x19\xa9\x11\x07\x9f\x9a3\x8d"\x83\x1c@\x9cF4iY'
    print("iv: {}".format(iv))
    print("salt: {}".format(salt))
    version = 1

    headerFrame = Backups_pb2.BackupFrame()
    headerFrame.header.iv = iv
    headerFrame.header.salt = salt
    headerFrame.header.version = version

    headerStr = headerFrame.SerializeToString()
    backup_file.write(struct.pack(">I", len(headerStr)))
    backup_file.write(headerStr)

    cipher_key, hmac_key = derive_keys(passphrase, salt)

    # Write the database: TODO
    # print("path: {}".format(input_directory))
    # database_path = Path(input_directory + "/" + "database.sqlite")
    # with open(database_path, "rb") as db_file:
    #     db_content = db_file.read()
    #     encrypted_db = encrypt_backup_frame(db_content, hmac_key, cipher_key, iv, version)
    #     iv = increment_initialisation_vector(iv)
    #     backup_file.write(encrypted_db)
    
    # # Write preferences: TODO
    # preferences_path = Path(input_directory + "/" + "preferences.json")
    # with open(preferences_path, "r") as prefs_file:
    #     preferences = json.load(prefs_file)
    #     preferences_data = json.dumps(preferences).encode("utf-8")
    #     encrypted_prefs = encrypt_backup_frame(preferences_data, hmac_key, cipher_key, iv, version)
    #     iv = increment_initialisation_vector(iv)
    #     backup_file.write(encrypted_prefs)
    
    keys = Keys(
        cipher_key=cipher_key,
        hmac_key=hmac_key,
    )

    # Add other files (attachments, avatars, etc.)
    iv = writeAttachmentObj(backup_file, keys, iv, input_directory, "attachments", AttachmentType.ATTACHMENT, version)
    iv = writeAttachmentObj(backup_file, keys, iv, input_directory, "avatars", AttachmentType.AVATAR, version)
    iv = writeAttachmentObj(backup_file, keys, iv, input_directory, "stickers", AttachmentType.STICKER, version)
    # Add similar steps for stickers, avatars, key-value files
    
    # Finalize the backup (add an end frame)
    footerFrame = Backups_pb2.BackupFrame()
    footerFrame.end = True

    footerStr = footerFrame.SerializeToString()
    encrypted_end_frame = encrypt_backup_frame(footerStr, hmac_key, cipher_key, iv, version)
    backup_file.write(encrypted_end_frame)

def derive_keys(passphrase: str, salt: bytes):
    # original code from decrypt_backup.py
    passphrase_bytes = passphrase.replace(" ", "").encode("ascii")

    hash = passphrase_bytes
    sha512 = Hash(algorithm=SHA512(), backend=DefaultBackend)
    sha512.update(salt)
    for _ in range(250000):
        sha512.update(hash)
        sha512.update(passphrase_bytes)
        hash = sha512.finalize()
        sha512 = Hash(algorithm=SHA512(), backend=DefaultBackend)

    hkdf = HKDF(algorithm=SHA256(), length=64, info=b"Backup Export", salt=b"", backend=DefaultBackend)
    keys = hkdf.derive(hash[:32])
    #print("derived cipherkey: {}".format(keys[:32]))
    #print("deviced hmackey: {}".format(keys[32:]))
    return Keys(
        cipher_key=keys[:32],
        hmac_key=keys[32:],
    )

def main():
    """Command-line interface to encrypt Signal backup."""
    passphrase = sys.argv[1]  # Get passphrase from user
    input_dir = sys.argv[2]  # Example input directory
    
    with open(sys.argv[3], "wb") as backup_file:
        create_backup_file(backup_file, passphrase, input_dir)

if __name__ == "__main__":
    main()
