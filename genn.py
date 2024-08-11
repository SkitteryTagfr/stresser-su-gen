from pytesseract import image_to_string, pytesseract
import random
import string
from base64 import b64decode
from curl_cffi.requests import Session
from PIL import Image
from io import BytesIO
from jwcrypto import jwk, jwe
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import threading

def import_key(pem_encoded_key):
    pem_contents = pem_encoded_key.strip()
    public_key = serialization.load_pem_public_key(
        pem_contents.encode('utf-8'),
        backend=default_backend()
    )

    return public_key


def encode_base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def convert_to_jwk(public_key):
    public_numbers = public_key.public_numbers()

    n = encode_base64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big'))
    e = encode_base64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big'))

    jwk_key = jwk.JWK(
        kty='RSA',
        n=n,
        e=e
    )
    return jwk_key


def generate_jwe(data):
    spki_pem = "-----BEGIN PUBLIC KEY-----\n    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzi65+rh9hW7nZ3TuPCCw\n    iMh63eBArhATyahT/a2mMVwoMeu7kp+/xG655h9D9pscQZt9w1F/qYglyq04Jl3b\n    mwdq50gcloPatldDOyYF55Cx9IvykXIj0i4p1A5dSv3h32Tzy7oFCUhFmTS9gDmb\n    YskxMRzKxbP8Hn/d3xVf7lkhBRBpNv/luyYgImolxs84EZUvhWUWmYt/D81oVOO0\n    bMJ1qZSjuTRAN88yzCi3PaqwC0uUTDERyUeA7pt6xXyyrklPirF0HOOS674GSJEn\n    3OTdalhoaxRbNjS101J6sc2aJoLiD78KkSVE7xC12J61TmMLcWcjezHHO1n4mRAY\n    iQIDAQAB\n    -----END PUBLIC KEY-----"

    public_key = import_key(spki_pem)
    jwk_key = convert_to_jwk(public_key)

    payload = json.dumps(data).encode('utf-8')
    protected_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM",
    }
    jwetoken = jwe.JWE(payload, recipient=jwk_key, protected=protected_header)
    jewcompact = jwetoken.serialize(True)

    return jewcompact
class RegTool:
    def __init__(self) -> None:
        self.session = Session(impersonate="chrome")

        self.session.headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'tr-TR,tr;q=0.8',
            'cache-control': 'no-cache',
            'expires': '0',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://stresser.su/register',
            'sec-ch-ua': '"Not)A;Brand";v="99", "Brave";v="127", "Chromium";v="127"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        self.session.cookies.update({'language': 'en'})
    def retry(self):
        while True:
            base64_image = self.session.get('https://stresser.su/request/view/getCaptcha').json()['response'].split('base64,')[1]
            image_data = b64decode(base64_image)
            image = Image.open(BytesIO(image_data))
            answer = image_to_string(image, config='--psm 6')
            if not answer:
                 print("Failed to get captcha, retrying...")
            else:
                 break

        self.session.headers['content-type'] = 'application/json'
        self.session.headers['origin'] = 'https://stresser.su'

        print(answer.strip())
        values = {
            "username": "".join(random.choices(string.ascii_letters + string.digits, k=12)),
            "password": "Test221!",
            "telegram": "",
            "captcha": answer.strip(),
            "lang": "en"
        }

        jwe_key = generate_jwe(values)
        json_data = {
           'JWE': jwe_key,
        }

        response = self.session.post('https://stresser.su/request/action/auth/register', json=json_data)
        print(response.status_code)
        if response.cookies.get('ACCESS_TOKEN') is not None:
            print("Account created successfully.")
            print(response.cookies.get('ACCESS_TOKEN'))
            acs = response.cookies.get("ACCESS_TOKEN")
            with open("accounts.txt", "a") as file:
                file.write(f"{acs}\n")
        else:
            self.retry()

    def generate_account(self):
        response = self.session.get('https://stresser.su/request/view/getCSRFToken')
        self.session.headers['x-xsrf-token'] = self.session.cookies["XSRF-TOKEN"]

        while True:
            base64_image = self.session.get('https://stresser.su/request/view/getCaptcha').json()['response'].split('base64,')[1]
            image_data = b64decode(base64_image)
            image = Image.open(BytesIO(image_data))
            answer = image_to_string(image, config='--psm 6')
            if not answer:
                print("Failed to get captcha, retrying...")
            else:
                break

        self.session.headers['content-type'] = 'application/json'
        self.session.headers['origin'] = 'https://stresser.su'

        print(answer.strip())
        values = {
            "username": "".join(random.choices(string.ascii_letters + string.digits, k=12)),
            "password": "Test221!",
            "telegram": "",
            "captcha": answer.strip(),
            "lang": "en"
        }

        jwe_key = generate_jwe(values)
        json_data = {
            'JWE': jwe_key,
        }

        response = self.session.post('https://stresser.su/request/action/auth/register', json=json_data)
        print(response.status_code)
        if response.cookies.get('ACCESS_TOKEN') is not None:
            print("Account created successfully.")
            print(response.cookies.get('ACCESS_TOKEN'))
            acs = response.cookies.get('ACCESS_TOKEN')
            with open("accounts.txt", "a") as file:
                file.write(f"{acs}\n")
        else:
            self.retry()
gen = RegTool()
def main():
    gen.generate_account()
if __name__ == '__main__':
    nr = int(input("How many accounts to create: "))
    for i in range(nr):
        main()
