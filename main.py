import threading
import gpiozero
import adc_dac
import key_share
import numpy as np
from encrypt_decrypt import encrypt_data, decrypt_data

# Define GPIO pins for Push-to-Talk (PTT) and an indicator LED
PTT_BUTTON_PIN = 17
LED_PIN = 27

# Setup GPIO for PTT button and LED
ptt_button = gpiozero.Button(PTT_BUTTON_PIN)
led = gpiozero.LED(LED_PIN)

# Initialize ADC/DAC
adc_dac.setup()

import numpy as np

# Function to handle the key sharing process
def button_key_share_pressed():
    # Share the public key and receive the peer's public key
    key_share.share_key()

def button_key_get_pressed():
    # Get the peer's public key and complete the key exchange
    key_share.get_peer_key()

def activate_ptt():
    # Replace with code to activate PTT on your radio dongle
    pass

def deactivate_ptt():
    # Replace with code to deactivate PTT on your radio dongle
    pass

def handle_transmission():
    while True:
        if ptt_button.is_pressed:
            led.on()
            print("Recording...")

            # Record audio using ADC
            recorded_data = adc_dac.record_audio(duration=2, fs=8000)

            # Encrypt the recorded data for transmission using the loaded public key
            encrypted_data = encrypt_data(recorded_data, public_key)  # Updated function call

            # Activate PTT
            activate_ptt()  # Activate PTT on your radio dongle

            # Deactivate PTT
            deactivate_ptt()  # Deactivate PTT on your radio dongle

            led.off()

def handle_reception():
    while True:
        received_audio = adc_dac.read_received_audio()  # Read received audio data from your ADC/DAC setup

        if received_audio:
            # Decrypt the received audio using the loaded private key
            decrypted_audio = decrypt_data(received_audio, private_key)  # Updated function call

            # Play the decrypted audio using ADC/DAC
            adc_dac.play_audio(decrypted_audio, fs=8000)


# Running transmission and reception in parallel threads
transmission_thread = threading.Thread(target=handle_transmission)
reception_thread = threading.Thread(target=handle_reception)

transmission_thread.start()
reception_thread.start()

# Join threads if the main thread is required to stay alive
transmission_thread.join()
reception_thread.join()
