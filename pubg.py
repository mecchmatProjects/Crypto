import ecdsa
import hashlib

def generate_key_pair_sequence(start_range, end_range, step=1):
    private_key = int(start_range, 16)

    while private_key <= int(end_range, 16):
        # Convert the private key to hexadecimal format
        private_key_hex = format(private_key, 'x').zfill(64)
        
        # Generate the corresponding public key
        signing_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        public_key = bytes.fromhex(verifying_key.to_string().hex())

        # Compress the public key manually
        compressed_public_key = bytes([2 + (verifying_key.pubkey.point.y() & 1)]) + verifying_key.pubkey.point.x().to_bytes(32, 'big')

        yield private_key_hex, compressed_public_key.hex(),public_key

        private_key += step

if __name__ == "__main__":
    start_range = input("Enter the starting range (hexadecimal format): ")
    end_range = input("Enter the ending range (hexadecimal format): ")
    step = int(input("Enter the step(hexadecimal)"),16)

    for private_key, compressed_public_key,public_key in generate_key_pair_sequence(start_range, end_range,step):
        print("Private Key:", private_key)
        print("Compressed Public Key:", compressed_public_key,len(compressed_public_key))
        #print("Public Key:", str(public_key), len(public_key))
        print("---------------------------")
