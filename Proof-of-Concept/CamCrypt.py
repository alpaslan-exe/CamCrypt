## Run "pip install opencv-python numpy cryptography pycryptodome sounddevice" to install dependecies required. ##this program takes aprox. 45 seconds to generate keys and 20 seconds at minimum, please be patient as it runs.

import cv2
import numpy as np
import sounddevice as sd
import time
import random
import hashlib

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

def is_static_frame(prev, curr, thresh=5000):
    if prev is None or curr is None:
        return False
    diff = cv2.absdiff(prev, curr)
    gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
    return cv2.countNonZero(gray) < thresh

class HMACDRBG:
    def __init__(self, seed: bytes):
        self.key = seed
        self.counter = 0
    def rand_bytes(self, n: int) -> bytes:
        result = b''
        while len(result) < n:
            ctr = self.counter.to_bytes(8, 'big')
            h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
            h.update(ctr)
            result += h.finalize()
            self.counter += 1
        return result[:n]

class CamMicEntropyGenerator:
    def __init__(self, duration_s=20, fps=10, samples=32, audio_rate=44100):
        self.duration_s = duration_s
        self.fps = fps
        self.samples = samples
        self.audio_rate = audio_rate
    def _lsb_frame(self, frame):
        bits = (frame & 1).flatten().tolist()
        return bytes(sum(((bits[i+j] << j) for j in range(8)), 0) for i in range(0, len(bits), 8))
    def _lsb_audio(self, audio):
        samples = audio.flatten().astype(np.int16)
        bits = (samples & 1).tolist()
        return bytes(sum(((bits[i+j] << j) for j in range(8)), 0) for i in range(0, len(bits), 8))
    def _collect_raw_seed(self):
        num = int(self.duration_s * self.audio_rate)
        audio = sd.rec(num, samplerate=self.audio_rate, channels=1, dtype='int16')
        cap = cv2.VideoCapture(0)
        frames = []
        start = time.time(); interval = 1.0/self.fps; next_t = start
        while time.time() - start < self.duration_s:
            now = time.time()
            if now >= next_t:
                ret, frame = cap.read()
                if ret: frames.append(frame.copy())
                next_t += interval
            cv2.waitKey(1)
        cap.release(); sd.wait()
        audio_bytes = self._lsb_audio(audio)
        frame_blobs = [self._lsb_frame(f) for f in frames]
        count = min(self.samples, len(frame_blobs))
        idxs = random.sample(range(len(frame_blobs)), count)
        mixed = b''
        for idx in idxs:
            blob = frame_blobs[idx]
            ts = int((idx/len(frame_blobs))*self.duration_s*1000).to_bytes(4,'little')
            mixed += hashlib.sha512(blob + audio_bytes + ts).digest()
        return hashlib.sha512(mixed).digest()[:32]
    def _seed_drbg(self):
        return HMACDRBG(self._collect_raw_seed())
    def generate_aes_128(self): return self._seed_drbg().rand_bytes(16)
    def generate_aes_256(self): return self._seed_drbg().rand_bytes(32)
    def generate_rsa_2048(self):
        drbg = self._seed_drbg()
        key = RSA.generate(2048, randfunc=drbg.rand_bytes)
        return key, key.publickey()
    def generate_rsa_4096(self):
        drbg = self._seed_drbg()
        key = RSA.generate(4096, randfunc=drbg.rand_bytes)
        return key, key.publickey()
    def generate_self_signed_cert(self, common_name="localhost", valid_days=365, rsa_bits=2048):
        if rsa_bits==4096: priv, pub = self.generate_rsa_4096()
        else: priv, pub = self.generate_rsa_2048()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(subject)
                .public_key(pub).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow()+timedelta(days=valid_days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(priv, hashes.SHA256(), default_backend()))
        return priv.export_key(format='PEM'), cert.public_bytes(serialization.Encoding.PEM)


def main():
    gen = CamMicEntropyGenerator()
    print("CamCrypt Proof-of-Concept")
    print("1) AES-128  2) AES-256  3) RSA-2048  4) RSA-4096  5) Self-signed SSL")
    choice = input("Select option [1-5]: ").strip()
    out_file = input("Save to file? (y/N): ").strip().lower() == 'y'
    if choice == '1':
        key = gen.generate_aes_128(); name = 'aes128.key'
        print("AES-128 key (hex):", key.hex())
    elif choice == '2':
        key = gen.generate_aes_256(); name='aes256.key'
        print("AES-256 key (hex):", key.hex())
    elif choice == '3':
        priv, pub = gen.generate_rsa_2048(); name='rsa2048'
        print(priv.export_key().decode())
    elif choice == '4':
        priv, pub = gen.generate_rsa_4096(); name='rsa4096'
        print(priv.export_key().decode())
    elif choice == '5':
        priv_pem, cert_pem = gen.generate_self_signed_cert(); name='ssl'
        print(cert_pem.decode())
    else:
        print("Invalid choice."); return
    if out_file:
        if choice in ['1','2']:
            with open(name, 'wb') as f: f.write(key)
        elif choice in ['3','4']:
            with open(f"{name}_priv.pem", 'wb') as f: f.write(priv.export_key())
            with open(f"{name}_pub.pem", 'wb') as f: f.write(pub.export_key())
        else:
            with open('cert.pem','wb') as f: f.write(cert_pem)
            with open('key.pem','wb') as f: f.write(priv_pem)
        print(f"Saved output to files with prefix '{name}'")

if __name__ == '__main__': main()
