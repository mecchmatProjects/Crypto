import ecdsa
import sys
import hashlib

CREATE_FILE = True
FNAME = "pubkeyslist.h"

HASH_FILE = None # "hash_pk.h"
HASH_FILE2 = "hash_pk2.h"

H_SIZE = 0x3FFFFFF
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

def Hash3(s):

    hash_res = 0

    p = 37
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

    a,b = 0x200000000000000000000000000000000, 0x3ffffffffffffffffffffffffffffffff
    c   = 0xa817291171418bbb8a8529a00c8c4d22
    # 1000000010000000
    # 10000000
    # 234049d583982292b95c152b0d0ab13f0b52caf1dc4dcde171ba007cf42
    d = ((b-a)//10000000)
    d = 940856
    print(f"{d:0x}")

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

        if FNAME is None:
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
            if HASH_FILE is not None:
                with open(HASH_FILE, "w") as f:
                    print("#include <stdlib.h>", file=f)
                    # print("\n\nint HASHES_PK[{}] = ".format(H_SIZE), file=f,end="")
                    # print("{0,};\n\n", file=f)
                    print("\n int* HASHES_PK;\n", file=f)
                    print("int* install_hash(){", file=f)
                    print("\n\tint* p = (int*) calloc({},sizeof(int));".format(H_SIZE), file=f)
                    print("\tif (!p) { ", file=f)
                    print("\t\tprintf(\"Cannot allocate {} size array!\");".format(H_SIZE), file=f)
                    print("\t\t return NULL;", file=f)
                    print("\t}\n", file=f)
                    print("\treturn p;\n", file=f)
                    print("}\n", file=f)
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

            print("File")
            if HASH_FILE2 is not None:
                print("HF2")
                with open(HASH_FILE2, "w") as f:
                    print("#include <stdlib.h>", file=f)
                    # print("\n\nint HASHES_PK[{}] = ".format(H_SIZE), file=f,end="")
                    # print("{0,};\n\n", file=f)
                    print("\n // for {}-{}, step {} \n".format(start_range, end_range, step), file=f)
                    print("\n int* HASHES_PK2;\n", file=f)
                    print("int* install_hash2(){", file=f)
                    print("\n\tint* p = (int*) calloc({},sizeof(int));".format(H_SIZE), file=f)
                    print("\tif (!p) { ", file=f)
                    print("\t\tprintf(\"Cannot allocate {} size array!\");".format(H_SIZE), file=f)
                    print("\t\t return NULL;", file=f)
                    print("\t}\n", file=f)
                    print("\treturn p;\n", file=f)
                    print("}\n", file=f)
                    print("void modify_array2(){\n", file=f)

                    count = 0
                    for private_key, compressed_public_key, public_key in generate_key_pair_sequence(start_range,
                                                                                                     end_range,
                                                                                                     step):
                        # print("Private Key:", private_key)
                        # print("Compressed Public Key:", compressed_public_key,len(compressed_public_key))
                        # print("Public Key:", str(public_key), len(public_key))
                        # print("---------------------------")
                        count += 1
                        # h = RSHash(compressed_public_key)
                        h = Hash3(compressed_public_key)
                        print("\tHASHES_PK2[" + str(h) + "]=" + str(count) + ";", file=f)

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
            print(Hash2(compressed_public_key))
