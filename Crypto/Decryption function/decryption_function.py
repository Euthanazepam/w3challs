from string import ascii_lowercase


def function(word: str, a: int, b: int, n: int) -> str:
    """
    Returns the result of the function f(x) = ax + b (mod n)
    This function can be used to encrypt and decrypt a word.

    :param a: Natural integers lower than n.
    :param b: Natural integers lower than n.
    :param n: Natural integer, modulus.
    :param word: Any word of plaintext or ciphertext.
    :return: Encrypted or decrypted word.
    """

    string = ""

    for w in word:
        word_number = ascii_lowercase.index(w)
        new_word_number = (((a * word_number) + b) % n)
        string += ascii_lowercase[new_word_number]

    return string


def reverse_function(a: int, b: int, n: int) -> tuple:
    """
    Returns the coefficients of the decryption function g(y) = a⁻¹ * (y - b) (mod n).

    :param a: Natural integers lower than n.
    :param b: Natural integers lower than n.
    :param n: Natural integer, modulus.
    :return: a⁻¹ (mod n), a⁻¹ * (-b) (mod n)
    """

    reverse_a = pow(a, -1, n)
    reverse_b = (reverse_a * (-b)) % n

    return reverse_a, reverse_b


def get_flag() -> str:
    """
    Returns the challenge flag https://w3challs.com/challenges/crypto/decryption_function

    :return: Flag
    """

    encrypted_word = function("GOOGLE".lower(), 21, 11, 26)

    a, b = reverse_function(21, 11, 26)
    decryption_function = f"{a}y+{b}[26]"

    decrypted_word = function("GELKT".lower(), a, b, 26)

    flag = f"{encrypted_word}_{decryption_function}_{decrypted_word}"

    # Bruteforce. I'll leave this here just for fun.
    #
    # n = 26
    # for i in range(26):
    #     for j in range(26):
    #         print(f"{'GOOGLE'.lower()}_{i}y+{j}[26]_{function('GELKT'.lower(), i, j, n)}")

    return flag


if __name__ == '__main__':
    print(get_flag())
