import re
import requests

base_url = "http://rsa-server.crypto.w3challs.com"
path_solution = "rsa.php"


def get_flag() -> str:
    """
    Returns the challenge flag https://w3challs.com/challenges/crypto/rsa_server
    According to http://factordb.com, N is a composite and has no known factors.
    Use a chosen ciphertext attack (CCA).
    If c₁ = m₁' mod N and c₂ = m₂' mod N, then c₁ * c₂ mod N = m₁' * m₂' mod N = (m₁ * m₂)' mod N

    Reference:
        1. Jean-Philippe Aumasson, Serious Cryptograph (2017), p. 279 - Breaking Textbook RSA Encryption’s Malleability,
        https://palaiologos.rocks/library/Serious%20Cryptography%20Jean-Philippe%20Aumasson.pdf

    :return: Flag
    """

    # Set headers.
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Get the task page.
    response = requests.get(f"{base_url}")

    # Find the numbers of the public key: N and e.
    public_key = re.search(r"N \(public module\) :\n(\d+)\n\n\ne \(public exponent\) :\n(\d+)", response.text)

    n = int(public_key.group(1))
    e = int(public_key.group(2))

    # Find the secret message.
    c = int(re.search(r"C :\n(\d+)", response.text).group(1))

    # Encrypt random text.
    random_message = int.from_bytes("Shut up and calculate".encode(), "big")
    c2 = pow(random_message, e, n)

    # Multiply two ciphertexts: c and c2.
    product_of_ciphertexts = (c * c2) % n

    # Decrypt the product of two ciphertexts.
    cmd = "DECRYPT"

    payload = f"""request=[RSA+Server+--+w3challs+--+1.0]
                    Send+me+a+command+and+its+argument.+Two+choices+are+possible:
                    1)+cmd+is+\"DECRYPT\"+arg+is+\"encrypted+message\"
                    2)+cmd+is+\"CODE\"+arg+is+\"Alice's+message\"
                    In+the+first+case,+the+message+provided+in+arg+(base+10+number)+is+decrypted+using+the+private+key+mentioned+in+the+description+of+this+challenge.+In+the+second+case+the+server+replies+with+the+flag+of+this+challenge,+only+is+arg+(Alice's+plaintext+message)+is+correct.\r\n\r\n
                    Fill+following+fields+and+click+on+'Send+the+packet'+:
                    cmd+=+\"{cmd}\"
                    arg+=+\"{product_of_ciphertexts}\""""

    response = requests.post(url=f"{base_url}/{path_solution}", headers=headers, data=payload)

    decrypted_message = int(re.search(r"Decrypted message : (\d+)", response.text).group(1))

    # Compute the plaintext message.
    message = (decrypted_message // random_message) % n

    # Send message to server.
    cmd = "CODE"

    payload = f"""request=[RSA+Server+--+w3challs+--+1.0]
                Send+me+a+command+and+its+argument.+Two+choices+are+possible:
                1)+cmd+is+\"DECRYPT\"+arg+is+\"encrypted+message\"
                2)+cmd+is+\"CODE\"+arg+is+\"Alice's+message\"
                In+the+first+case,+the+message+provided+in+arg+(base+10+number)+is+decrypted+using+the+private+key+mentioned+in+the+description+of+this+challenge.+In+the+second+case+the+server+replies+with+the+flag+of+this+challenge,+only+is+arg+(Alice's+plaintext+message)+is+correct.\r\n\r\n
                Fill+following+fields+and+click+on+'Send+the+packet'+:
                cmd+=+\"{cmd}\"
                arg+=+\"{message}\""""

    response = requests.post(url=f"{base_url}/{path_solution}", headers=headers, data=payload)

    # Find the task flag.
    flag = re.findall("W3C{.*}", response.text)

    return flag[0]


if __name__ == "__main__":
    print(get_flag())
