import re
import requests

from random import randint

base_url = "http://asymmetric-encryption.crypto.w3challs.com"
path_solution = "index.php"
query_solution = "p=solution"


class AsymmetricEncryption:
    """
    Implementation of asymmetric encryption from the task https://w3challs.com/challenges/crypto/asymmetric_encryption
    Used to analyze the operation of the encryption/decryption algorithm.

    PHP implementation is available here — http://asymmetric-encryption.crypto.w3challs.com/implementation.php
    """

    @staticmethod
    def gen_key() -> tuple:
        """
        Generates and returns public and private keys.

        :return: public key (h, f) and private key (g)
        """

        a = randint(0, 2 ** 192)
        b = randint(0, 2 ** 192)
        c = randint(0, 2 ** 192)
        d = randint(0, 2 ** 192)

        e = (a * b) - 1
        f = (c * e) + a # Public exponent
        g = (d * e) + b # Private key
        h = (c * d * e) + (a * d) + (b * c) + 1 # Modulus

        public_key = (h, f)
        private_key = g

        keys = (public_key, private_key)

        return keys

    @staticmethod
    def encrypt(m: int, public_key: tuple) -> int:
        """
        Encrypts the plaintext and returns the ciphertext.

        :param m: plaintext as an integer
        :param public_key: public key as a pair of integers
        :return: ciphertext as an integer
        """

        c = m * public_key[1] % public_key[0]   # m * f % h

        return c

    @staticmethod
    def decrypt(c: int, public_key: tuple, private_key: int) -> int:
        """
        Decrypts the ciphertext and returns the plaintext.

        :param c: ciphertext as an integer
        :param public_key: public key as a pair of integers
        :param private_key: private key as an integer
        :return: plaintext as an integer
        """

        m = c * private_key % public_key[0] # c * g % h

        return m


def get_flag() -> str:
    """
    Returns the challenge flag https://w3challs.com/challenges/crypto/asymmetric_encryption
    According to the implementation of asymmetric encryption:
        C = m * f % h,
        m = C * g % h

    Therefore, f * g % h must be equal to 1. So, g = f⁻¹ % h

    :return: Flag
    """

    # All requests must be sent within one session.
    session = requests.Session()

    # Get the task page.
    response = session.get(f"{base_url}")

    # Find the numbers of the public key: h and f.
    public_key = re.search(r"h = (\d+)\n\nf = (\d+)", response.text)

    h = int(public_key.group(1))
    f = int(public_key.group(2))

    # Find the secret message.
    c = int(re.search(r"C : (\d+)", response.text).group(1))

    # Compute the secret key.
    g = pow(f, -1, h)

    # Decrypt encrypted message.
    message = c * g % h

    # Send message.
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    payload = f"mess={message}"

    response = session.post(url=f"{base_url}/{path_solution}?{query_solution}", headers=headers, data=payload)

    # Find the task flag.
    flag = re.findall("W3C{.*}", response.text)

    return flag[0]


if __name__ == "__main__":
    print(get_flag())
