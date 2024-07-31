def extended_gcd(a: int, b: int) -> int:
    """
    Returns the secret exponent.

    :param a: e, public exponent
    :param b: phi, value of Euler's totient function
    :return: d, secret exponent
    """

    # Snatch from https://brilliant.org/wiki/extended-euclidean-algorithm.
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n

    return x


def rsa_decrypt(c: int, d: int, n: int) -> str:
    """
    Returns the decrypted message.

    :param c: Encrypted message (integer)
    :param d: Secret exponent
    :param n: Modulus
    :return: Decrypted message (text)
    """

    # The key length is 8 bits.
    decrypted_text = pow(c, d, n).to_bytes(8, 'big').decode()

    return decrypted_text


def get_flag() -> str:
    """
    https://w3challs.com/challenges/crypto/rsa
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

    """
    References:
        1. RSA Decoder — https://www.dcode.fr/rsa-cipher
        2. FactorDB — http://factordb.com
    """

    # Use http://factordb.com to factorize n
    p = 27789079547
    q = 28188776653

    phi = (p - 1) * (q - 1)
    d = extended_gcd(a=e, b=phi)

    flag = ''

    for c in cipher:
        flag += rsa_decrypt(c=c, d=d, n=n)

    return flag


if __name__ == '__main__':
    print(get_flag())
