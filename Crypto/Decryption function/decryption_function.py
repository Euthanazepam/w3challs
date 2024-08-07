from string import ascii_lowercase


def function(word: str, a: int, b: int, n: int) -> str:
    """
    Returns the result of the function f(x) = ax + b (mod 26)
    This function can be used to encrypt and decrypt a word.

    :param a: Natural integers lower than 26.
    :param b: Natural integers lower than 26.
    :param n: Natural integer, modulus.
    :param word: Any word of plaintext or ciphertext.
    :return: Encrypted or decrypted word.
    """

    string = ''

    for w in word:
        word_number = ascii_lowercase.index(w)
        new_word_number = (((a * word_number) + b) % n)
        string += ascii_lowercase[new_word_number]

    return string


def get_flag() -> str:
    """
    Returns the challenge flag https://w3challs.com/challenges/crypto/decryption_function

    :return: Flag
    """

    # The function f(x) = 21x + 11 is used for encryption
    encrypted_word = function("GOOGLE".lower(), 21, 11, 26)

    decryption_function = "5y+23[26]"

    # The function g(y) = 5y + 23 is used for decryption
    decrypted_word = function("GELKT".lower(), 5, 23, 26)

    flag = f"{encrypted_word}_{decryption_function}_{decrypted_word}"

    # Bruteforce
    # n = 26
    # for i in range(26):
    #     for j in range(26):
    #         print(f"{'GOOGLE'.lower()}_{i}y+{j}[26]_{function('GELKT'.lower(), i, j, n)}")

    return flag


if __name__ == '__main__':
    print(get_flag())
