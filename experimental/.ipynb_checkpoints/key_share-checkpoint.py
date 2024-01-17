from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sounddevice as sd
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants for modulation and demodulation
SAMPLE_RATE = 44100  # Sample rate in Hz
CARRIER_FREQUENCY = 1000  # Carrier frequency in Hz
BIT_RATE = 1200  # Bit rate in bits per second
BIT_DURATION = int(SAMPLE_RATE / BIT_RATE)
FREQUENCY_SHIFT = 100  # Frequency shift in Hz

# Define global variables for shared_key and peer_public_key_bytes
shared_key = None
peer_public_key_bytes = None

# Function to generate DH parameters and private key
def generate_private_key():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters.generate_private_key()

# Function to serialize public key
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Function to deserialize a peer's public key
def deserialize_peer_public_key(peer_public_key_bytes):
    return serialization.load_pem_public_key(
        peer_public_key_bytes,
        backend=default_backend()
    )

# Function to perform the key exchange
def perform_key_exchange(private_key, peer_public_key_bytes):
    peer_public_key = deserialize_peer_public_key(peer_public_key_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# Function to derive a symmetric key from the shared secret
def derive_symmetric_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

# Function to share the public key with a peer
def share_key():
    global shared_key
    global peer_public_key_bytes

    my_private_key = generate_private_key()  # Generate your private key
    my_public_key = my_private_key.public_key()  # Generate your public key

    # Serialize and exchange public keys
    my_public_key_bytes = serialize_public_key(my_public_key)
    peer_public_key_bytes = exchange_public_keys(my_public_key_bytes)

    # Perform key exchange and derive symmetric key
    shared_secret = perform_key_exchange(my_private_key, peer_public_key_bytes)
    shared_key = derive_symmetric_key(shared_secret)

# Function to get the shared key
def get_key():
    global shared_key
    return shared_key

# Function to transmit audio signal over radio
def radio_transmit(audio_signal):
    # Ensure that your Raspberry Pi is configured to output audio through the radio hardware.
    # You may need to configure audio output settings and interface with your radio hardware.
    # Example code for transmitting audio via sounddevice:
    sd.play(audio_signal, SAMPLE_RATE)
    sd.wait()

# Function to receive audio signal over radio
def radio_receive():
    # Ensure that your Raspberry Pi is configured to capture audio from the radio hardware.
    # You may need to configure audio input settings and interface with your radio hardware.
    # Example code for receiving audio via sounddevice:
    received_audio_signal = sd.rec(BIT_DURATION, SAMPLE_RATE)
    sd.wait()
    return received_audio_signal

# Example usage of the key exchange and symmetric key derivation
if __name__ == "__main__":
    # Example usage to share the key
    share_key()

    # Get the shared key
    symmetric_key = get_key()

    # You can now use 'symmetric_key' for encrypting and decrypting your radio communication.
    # Modify and integrate this script into your radio dongle application as needed.

