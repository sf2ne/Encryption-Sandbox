# Sadiyah Faruk, sf2ne


from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import ARC4


def secret_string(string, public_key):
    """Takes in a string and a public key, encrypts the string with said
    key, then returns the resulting string"""
    enc_data = public_key.encrypt(string.encode(), 32)
    return enc_data[0]


def encrypt_file(file_name, symmetric_key):
    """Goes to the file, opens it, encrypts its contents with the key given, and writes the encrypted version to the
    same filename as the original, but with “.enc” appended to the end. For example, given
    “helloworld.txt” and some key, the function produces “helloworld.txt.enc”. Return true if the encryption was
    successfully completed."""
    try:
        # iv = Random.new().read(DES3.block_size)
        # des3 = DES3.new(symmetric_key, DES3.MODE_CFB, iv)
        # aes_machina = AES.new(symmetric_key, AES.MODE_CFB, iv)
        try:
            f = open(file_name, 'rb')
            file2 = file_name + ".enc"
            f2 = open(file2, 'wb')
        except FileNotFoundError:
            print("File was not found or could not be opened")
        with f as input_file:
            with f2 as encrypted_file:
                while True:
                    chunk = input_file.read(64*1024)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    encrypted_file.write(symmetric_key.encrypt(chunk))
        return True
    except:
        return False


def decrypt_file(file_name, symmetric_key):
    """Opens the file and decrypts it with the symmetric key. Saves the file with the original filename (i.e.
    remove the “.enc” from the end) but with “DEC_” as a prefix. For example,
    “hello_world.txt.enc” should become “DEC_hello_world.txt”. This file should be identical to the file
    originally encrypted (assuming the key used to decrypt is the same as the key to encrypt). Return
    true if the decryption was successful."""
    try:
        # iv = Random.new().read(AES.block_size)
        # aes_machina = AES.new(symmetric_key, AES.MODE_CFB, iv)
        try:
            f = open(file_name, 'rb')
            file2 = "DEC_" + file_name
            file2 = file2[:-4]
            f2 = open(file2, 'wb')
        except FileNotFoundError:
            print("File was not found or could not be opened")
        with f as enc_file:
            with f2 as decrypted_file:
                while True:
                    chunk = enc_file.read(64*1024)
                    if len(chunk) == 0:
                        break
                    # elif len(chunk) % 16 != 0:
                    #     chunk += ' ' * (16 - len(chunk) % 16)
                    decrypted_file.write(symmetric_key.decrypt(chunk))
        return True
    except:
        return False


def test_secret_string():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    pub_key = key.publickey()
    secret = "Suppose we wish to create a classifier for a dataset"
    out_string = secret_string(secret, pub_key)
    print(out_string)


def test_encrypt_file():
    # test text file .txt
    file_name = 'test_encr.txt'
    random_generator = Random.new().read
    # priv_key = RSA.generate(1024, random_generator)
    priv_key = 'abcd'
    symm_key = ARC4.new(priv_key)
    if encrypt_file(file_name, symm_key):
        print("Try to open the file and see what you got")
    else:
        print("Something went wrong")

    # test image file .jpg
    file_name = 'birb_flower.jpg'
    if encrypt_file(file_name, symm_key):
        print("Try to open the file and see what you got")
    else:
        print("Something went wrong")


def test_encrypt_file_binary():
    # test text file .txt
    file_name = 'binary.txt'
    random_generator = Random.new().read
    # priv_key = RSA.generate(1024, random_generator)
    priv_key = 'abcd'
    symm_key = ARC4.new(priv_key)
    if encrypt_file(file_name, symm_key):
        print("Try to open the file and see what you got")
    else:
        print("Something went wrong")


def test_decrypt_file():
    # test text file .txt
    file_name = 'test_encr.txt.enc'
    # random_generator = Random.new().read
    # priv_key = RSA.generate(1024, random_generator)
    priv_key = 'abcd'
    symm_key = ARC4.new(priv_key)
    if decrypt_file(file_name, symm_key):
        print("Try to open the file and see what you got")
    else:
        print("Something went wrong")

    # test image file .jpg
    file_name = 'birb_flower.jpg.enc'
    if decrypt_file(file_name, symm_key):
        print("Try to open the file and see what you got")
    else:
        print("Something went wrong")


def test_decrypt_file_binary():
    # test text file .txt
    file_name = 'binary.txt.enc'
    # random_generator = Random.new().read
    # priv_key = RSA.generate(1024, random_generator)
    priv_key = 'abcd'
    symm_key = ARC4.new(priv_key)
    if decrypt_file(file_name, symm_key):
        print("Try to open the file and see what you got")
    else:
        print("Something went wrong")


if __name__ == "__main__":
    # test_secret_string()
    # test_encrypt_file()
    # test_decrypt_file()
    # test_encrypt_file_binary()
    # test_decrypt_file_binary()

