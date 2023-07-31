import ecdsa
import hashlib


def generate_key_pair_sequence():
    private_key = int("0000000000000000000000000000000000000000000000000000000000000001", 16)

    while True:
        # Convert the private key to hexadecimal format
        private_key_hex = format(private_key, 'x').zfill(64)

        # Generate the corresponding public key
        signing_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        public_key = bytes.fromhex(verifying_key.to_string().hex())

        # Compress the public key manually
        compressed_public_key = bytes(
            [2 + (verifying_key.pubkey.point.y() & 1)]) + verifying_key.pubkey.point.x().to_bytes(32, 'big')

        yield private_key_hex, compressed_public_key.hex()

        private_key += 1
        if private_key_hex == "00000000000000000000000000000000000000000000000000000fffffffffff":
            break


if __name__ == "__main__":
    for private_key, compressed_public_key in generate_key_pair_sequence():
        print("Private_k:", private_key, "Public_k:", compressed_public_key)