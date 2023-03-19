from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def derive_key(password, salt):
    """
    Deriva una clave a partir de una contraseña y una sal.
    """
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    password = password.encode("utf-8")
    key = scrypt(password, salt=salt, key_len=32, N=2**14, r=8, p=1)
    return key

def encrypt_text(password, text):
    """
    Cifra un texto usando una contraseña y devuelve el resultado cifrado y la sal utilizada.
    """
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    text = text.encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(text)
    iv = cipher.nonce
    result = salt + iv + len(tag).to_bytes(2, byteorder="big") + ciphertext + tag
    return result

def decrypt_text(password, data):
    """
    Descifra un texto cifrado usando una contraseña y devuelve el resultado descifrado.
    """
    salt = data[:16]
    iv = data[16:32]
    tag_size = int.from_bytes(data[32:34], byteorder="big")
    ciphertext = data[34:-tag_size]
    tag = data[-tag_size:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise Exception("Incorrect password or file has been modified.")
    return plaintext.decode("utf-8")

def encrypt_file(password, input_file, output_file):
    """
    Encripta un archivo usando una contraseña y escribe el resultado en otro archivo.
    """
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    with open(input_file, 'rb') as f:
        text = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(text)
    iv = cipher.nonce
    result = salt + iv + len(tag).to_bytes(2, byteorder="big") + ciphertext + tag
    with open(output_file, "wb") as f:
        f.write(result)

def decrypt_file(password, input_file, output_file):
    """
    Descifra un archivo cifrado usando una contraseña y escribe el resultado en otro archivo.
    """
    with open(input_file, 'rb') as f:
        data = f.read()
    salt = data[:16]
    iv = data[16:32]
    tag_size = int.from_bytes(data[32:34], byteorder="big")
    ciphertext = data[34:-tag_size]
    tag = data[-tag_size:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise Exception("Incorrect password or file has been modified.")
    with open(output_file, "wb") as f:
        f.write(plaintext)

def save_text(password, text, output_file):
    """
    Cifra un texto usando una contraseña y escribe el resultado cifrado en un archivo.
    """
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    iv = cipher.nonce
    result = salt + iv + len(tag).to_bytes(2, byteorder="big") + ciphertext + tag
    with open(output_file, "wb") as f:
        f.write(result)