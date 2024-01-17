import base64
import subprocess

def call_ntru_script(action, key_file, data=None):
    command = ['./ntru.py', action, key_file]
    if data:
        # Assuming data is already a bytes object.
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_data, stderr_data = process.communicate(input=data)
    else:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_data, stderr_data = process.communicate()

    if process.returncode != 0:
        raise Exception(f"ntru.py failed: {stderr_data.decode()}")
    
    return stdout_data

def encrypt_data(data):
    # Assuming data is a bytes object, convert it to Base64 to ensure safe transmission through subprocess
    data_base64 = base64.b64encode(data)
    encrypted_data = call_ntru_script('enc', 'public_key.npz', data_base64)
    return encrypted_data

def decrypt_data(encrypted_data, key_file):
    # Decrypt and then decode from Base64
    decrypted_data = call_ntru_script('dec', key_file, encrypted_data)
    return base64.b64decode(decrypted_data)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NTRUEncrypt Encryption and Decryption")
    parser.add_argument("action", choices=["enc", "dec"], help="Action to perform")
    parser.add_argument("data", help="Data to encrypt/decrypt")

    args = parser.parse_args()

    if args.action == "enc":
        # Convert string data to bytes before encryption
        encrypted_data = encrypt_data(args.data.encode())
        print("Encrypted Data:", base64.b64encode(encrypted_data).decode())
    elif args.action == "dec":
        # Decode Base64 encoded string to bytes before decryption
        decrypted_data = decrypt_data(base64.b64decode(args.data), 'private_key.npz')
        print("Decrypted Data:", decrypted_data.decode())
