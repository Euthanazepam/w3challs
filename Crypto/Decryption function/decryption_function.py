from string import ascii_lowercase


def function(word: str, a: int, b: int) -> str:
    """
    Returns the result of the function f(x) = ax + b (mod 26)
    This function can be used to encrypt and decrypt a word.

    :param a: Natural integers lower than 26.
    :param b: Natural integers lower than 26.
    :param word: Any word of ciphertext.
    :return: Encrypted or decrypted word.
    """

    string = ''

    for w in word:
        word_number = ascii_lowercase.index(w)
        new_word_number = (((a * word_number) + b) % 26)
        string += ascii_lowercase[new_word_number]

    return string


def get_flag() -> str:
    """
    https://w3challs.com/challenges/crypto/decryption_function
    """

    flag = ''

    # The function f(x) = 21x + 11 is used for encryption
    encrypt_word = function('GOOGLE'.lower(), 21, 11)
    encrypted_word = "GELKT".lower()

    for i in range(26):
        for j in range(26):
            # The word "bravo" was the only human-readable word found in the brute force process.
            if 'bravo' in function(encrypted_word, i, j):
                flag = f"{encrypt_word}_{i}y+{j}[26]_{function(encrypted_word, i, j)}"

    return flag


if __name__ == '__main__':
    print(get_flag())
