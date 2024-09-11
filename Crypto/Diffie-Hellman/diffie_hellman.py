import re   # If you have a problem, and you're going to solve it with regular expressions, you now have two problems
import requests

base_url = "http://diffie-hellman.crypto.w3challs.com"

path_dh_challenge = "challenge_diffie_hellman.php"
path_dh_key = "dhkey.php"
path_solution = "solution_diffie_hellman.php"

query_alice = "alice_send_key"
query_bob = "bob_send_key"


def get_flag() -> str:
    """
    Returns the challenge flag https://w3challs.com/challenges/crypto/diffie_hellman

    :return: Flag

    A bit of theory:
        p — modulus
        g — base
        a, b — secret integers

        A = pow(g, a, p)
        B = pow(g, b, p)

        s — shared secret

        s = pow(B, a, p) = pow(A, b, p) = pow(g, a*b, p)
    """

    # All requests must be sent within one session
    session = requests.Session()

    # Get the task page
    response = session.get(f"{base_url}/{path_dh_challenge}")

    # Find the numbers p and g
    match = re.search(r"p =\n(\d+)\n\ng = (\d+)", response.text)

    p = int(match.group(1))
    g = int(match.group(2))

    # Get the iframe containing the sniffer
    response = session.get(f"{base_url}/{path_dh_key}")

    # Find Alice's public key
    A = int(re.search(r"A = (\d+)", response.text).group(1))

    # Send Alice's packet to Bob
    alice_payload = {
        query_alice: f"""[ --------- w3challs-Sniffer 1.4.7 --------- ]\n\n
        Message from Alice to Bob on 2023/09/03 22:19:07\n\n
        "Hey Bob, if I don't receive your B in about thirty seconds maximum, I'll consider this channel unsafe\n\n
        A = {A}\""""
    }

    response = session.post(url=f"{base_url}/{path_dh_key}?type={query_alice}", data=alice_payload)

    # Choose any secret key and compute Bob's public key
    b = 5
    B = pow(g, b, p)

    # Compute the shared secret key
    s = pow(A, b, p)

    # Send Bob's packet to Alice (she will think that it was Bob who sent her the packet)
    bob_payload = {
        query_bob: f"""[ --------- w3challs-Sniffer 1.4.7 --------- ]\n\n
        Message from Bob to Alice on 2023/09/03 22:24:15\n\n
        "Hey Alice, here is my B :\n\n
        B = {B}\""""
    }

    response = session.post(url=f"{base_url}/{path_dh_key}?type={query_bob}", data=bob_payload)

    # Find the encrypted code
    c = int(re.search(r"(\d+)\"", response.text).group(1))

    # Compute the password using XOR between the encrypted code and the shared secret key
    password = c ^ s

    # Send password to specified URL
    response = session.get(f"{base_url}/{path_solution}?password={password}")

    # Find the task flag
    flag = re.findall("W3C{.*}", response.text)

    # Sometimes the server returns a response that the password is incorrect
    try:
        return flag[0]
    except IndexError:
        return response.text


if __name__ == "__main__":
    print(get_flag())
