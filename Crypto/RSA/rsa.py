from factordb.factordb import FactorDB


def rsa_decrypt(c: int, d: int, n: int) -> str:
    """
    Returns the decrypted message.

    :param c: Encrypted message (integer)
    :param d: Secret exponent
    :param n: Modulus
    :return: Decrypted message (text)
    """

    decrypted_text = pow(c, d, n).to_bytes(c.bit_length() // 8, 'big').decode()

    return decrypted_text


def get_flag() -> str:
    """
    Returns the challenge flag https://w3challs.com/challenges/crypto/rsa

    References:
        1. RSA Decoder — https://www.dcode.fr/rsa-cipher
        2. FactorDB — http://factordb.com

    :return: Flag
    """

    cipher = [
        309117097659990665453,
        125675338953457551017,
        524099092120785248852,
        772538252438953530955,
        547462544172248492882,
        28215860448757441963,
        543018082275730030658,
        585936545563088067075,
        131807465077304821584
    ]

    n = 783340156742833416191
    e = 653

    # Use http://factordb.com to factorize n
    f = FactorDB(n)
    f.connect()
    p, q = f.get_factor_list()

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    flag = ''

    for c in cipher:
        flag += rsa_decrypt(c=c, d=d, n=n)

    return flag


if __name__ == '__main__':
    print(get_flag())
