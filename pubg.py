import ecdsa
import sys
import hashlib

CREATE_FILE = True
FNAME = "pubkeyslist.h"

HASH_FILE = "hash_pk.h"
H_SIZE = 0xFFFFFFF
def RSHash(s):

    b = 378551
    a = 63689
    hash_res = 0

    for c in s:
        hash_res = (hash_res * a + int(c,16)) % H_SIZE
        a *= b
        a = a % H_SIZE
    return hash_res

def Hash2(s):

    hash_res = 0

    p = 31
    for c in s:
        hash_res *= p
        hash_res %= H_SIZE
        hash_res += int(c,16)
        hash_res %= H_SIZE
        # print(hash_res)
    return hash_res

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
        compressed_public_key = bytes(
            [2 + (verifying_key.pubkey.point.y() & 1)]) + verifying_key.pubkey.point.x().to_bytes(32, 'big')

        yield private_key_hex, compressed_public_key.hex(), public_key

        private_key += step


if __name__ == "__main__":

    if len(sys.argv) <= 2:
        start_range = input("Enter the starting range (hexadecimal format): ")
        end_range = input("Enter the ending range (hexadecimal format): ")
        step = int(input("Enter the step(hexadecimal)"), 16)
    elif len(sys.argv) == 3:
        start_range = sys.argv[1]
        end_range = sys.argv[2]
        step = 1
    else:
        start_range = sys.argv[1]
        end_range = sys.argv[2]
        step = int(sys.argv[3],16)

    if CREATE_FILE:

        if HASH_FILE is None:
            with open(FNAME, "w") as f:
                print("#include <stdio.h>", file=f)
                print("\n\nchar* RANGE_PK [] = {", file=f)
                for private_key, compressed_public_key, public_key in generate_key_pair_sequence(start_range, end_range,
                                                                                                 step):
                    # print("Private Key:", private_key)
                    # print("Compressed Public Key:", compressed_public_key,len(compressed_public_key))
                    # print("Public Key:", str(public_key), len(public_key))
                    # print("---------------------------")
                    print("\"" + compressed_public_key + "\", ", file=f)
                print("};\n", file=f)
                print(file=f)

        else:
            with open(HASH_FILE, "w") as f:
                print("#include <stdio.h>", file=f)
                print("\n\nint HASHES_PK[{}] = ".format(H_SIZE), file=f,end="")
                print("{0,};\n\n", file=f)

                print("void modify_array(){\n",file=f)

                count = 0
                for private_key, compressed_public_key, public_key in generate_key_pair_sequence(start_range, end_range,
                                                                                                 step):
                    # print("Private Key:", private_key)
                    # print("Compressed Public Key:", compressed_public_key,len(compressed_public_key))
                    # print("Public Key:", str(public_key), len(public_key))
                    # print("---------------------------")
                    count += 1
                    #h = RSHash(compressed_public_key)
                    h = Hash2(compressed_public_key)
                    print("\tHASHES_PK[" + str(h) + "]=" + str(count) + ";", file=f)

                print("};\n", file=f)
                print(file=f)

        print("done")
    else:
        for private_key, compressed_public_key, public_key in generate_key_pair_sequence(start_range, end_range, step):
            # print("Private Key:", private_key)
            # print("Compressed Public Key:", compressed_public_key,len(compressed_public_key))
            # print("Public Key:", str(public_key), len(public_key))
            # print("---------------------------")
            print("\"" + compressed_public_key + "\", ")
            # Hash2(compressed_public_key)