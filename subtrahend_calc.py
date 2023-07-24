import subprocess
import os

DEBUG_SCRIPT = True  # debug code

TEST_SUB = True  # test subtraction
TEST_MAIN = True  # test get subtrahend

"""
 Calls mel.exe to get the difference public key
 args:
 @param x:str - value of the private key 
 @param n:int - integer to subtract
 :return
 The public key of difference    
"""
def subtract(x, n):
    if DEBUG_SCRIPT:
        print("./mel.exe -p %s -s -n 1 -r 1:%x -o test.txt"%(x,n))

    # maybe we need to eradicate echo output with NULL = open(os.devnull, 'w')
    # FIXME: HAYWIRE script approach - should be done in C code

    d = subprocess.run(["mel.exe", "-p", "%s"%(x), "-s", "-n", "1", "-r", "1:%x"%(n),"-x"], capture_output=True,
                       text=True).stdout

    # Not safe
    # TODO: after modification of script by performing one operation
    # TODO: check all possible errors
    try:
        d = d.split("\n")[-6].split()[0]
    except Exception as e:
        print(f"Subtraction error:{d}")
        return None

    if DEBUG_SCRIPT:
        print("d=", d)

    return d


"""
 Apply binary search to calculate the subtrahend that 
 make difference to be within range specified by public keys   
 :arg
 @param: x[str] - public key of subtracted point(target)
 @param: a[int] - left boundary of known interval 
 @param: b[int] - right boundary of known interval
 @param: PubKey0[str] - left boundary of desired interval public key 
 @param: PubKey1[str] - right boundary of desired interval public key
 :return
 value of desired subtrahend     
"""
def getSubtrahend(x, a, b, PubKey0, PubKey1):
    mid = (a + b) // 2

    if mid <= a:
        return mid

    pubkeyNew = subtract(x, mid)
    if pubkeyNew is None:
        print("Please check Your target key")
        input()
        return None


    if DEBUG_SCRIPT:
        print("\n \n Mid ", mid, a, b, pubkeyNew, PubKey0, PubKey1)
        # input()

    if pubkeyNew[-len(PubKey0):] < PubKey0:
        return getSubtrahend(x, a, mid, PubKey0, PubKey1)

    elif pubkeyNew[-len(PubKey1):] > PubKey1:
        return getSubtrahend(x, mid,b, PubKey0, PubKey1)

    PubKey00 = PubKey0[:-5] + "FFFFF"
    print("PK", PubKey00)
    if pubkeyNew[-len(PubKey0):] > PubKey0:
        return getSubtrahend(x, mid, b, PubKey0, PubKey1)

    return mid

KEY_ONE = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
KEY_TWO = "035E95BB399A6971D376026947F89BDE2F282B33810928BE4DED112AC4D70E20D5"

def testSubtract():
    # x = "03CF62F121200F56C503DC6CEC1AA862E03B6B85D84D9D4026F093A254D62DC72B" #
    x_tests = ["03EA1CC79FF6BE554FB04333AE959958C71CB54E7A8403258CB9B7781394B416C9",
               "03CF62F121200F56C503DC6CEC1AA862E03B6B85D84D9D4026F093A254D62DC72B"
              ]

    for i in range(-5, 5):
        for x in x_tests:
            res = subtract(x, int(x, 16) + i)
            print(f"\n subtract result for {i}: {res}")
            # input()


def testSubtrahend():
    NEED_INTERVAL_MIN = 0x1
    NEED_INTERVAL_MAX = 0xFFFFFF

    PK_START = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    PK_END   = "0327E68D344D61A48DBB9546F706DF34897E3CE1B7B40D0766F0DEB58361BD74EE"

    LOOKED_INT_MIN = 0x00000000200000000000000
    LOOKED_INT_MAX = 0x00000000500000000000000
    #               2BFFFFFFFFFFFFFFFFFFFFFFFFF

    target_n = (LOOKED_INT_MIN + LOOKED_INT_MAX)//2
    target1 = "02ACEE878372685CA862D60055D0655F6E3DB9605E329CDEE4C1ACFB9D5AF59862"
    n = getSubtrahend(target1, LOOKED_INT_MIN, LOOKED_INT_MAX, PK_START, PK_END)
    print("\n n=", n)
    # 2BFFFFFFFFFFFFFFFFFFFFFFFFF
    test_it = subtract(target1, n)
    print("test n:",test_it)
    # input()

##########################
# BASIC TESTS
if TEST_SUB:
    testSubtract()
if TEST_MAIN:
    testSubtrahend()

if __name__ == "__main__":

    START = 0x000000000000200000000000000000000000000
    END = 0x000000000000003ffffffffffffffffffffffffff

    START_NEW = 0x0000000000000000000000000000000000000000000000000000000000000001
    END_NEW = 1000000

    # 1020847100762815390390123822295304634369
    # public 5HpHagT65TZzG1PH3CSu649jkvD5x9fGYxstEap59ucLQcH1pxj
    # private 03CF62F121200F56C503DC6CEC1AA862E03B6B85D84D9D4026F093A254D62DC72B
    # dec 441179842594957130278973409334323152175017054977628378887208019926257543005995

    PubKey0 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"  # Public key of START_NEW
    PubKey1 = "02CE9FF4C0B094BA34B93EC9CD0164CCCC308EB4D5F600FAA06D29BD8CAADB6A0F"  # Public key of END_NEW

    START_NEW, END_NEW =0x20000000000, 0x3ffffffffffffffffff

    # 2199023255552, 18889465931478580854783
    """
    PubKey0 = "0396083F9F6DD0CDFD5697867C9D0B1A968BD598D8EAFA62DC1E25752EFE4A63E8"
    PubKey1 = "02FAA6E8691C0A073BE85D68DE24C3DD716E2238491F700700D6E07E9328F20272"
    """
    PubKey0 = "03fd136eef8971044e8a3a43622003a26703ecaf7a0ec40c3fba5b594b77078424"
    PubKey1 = "02db009a8eca6a87bcd54ac948f0b59e1ba6a4519da47f807c1b3ee79f09467453"


    START = 0x40000000000000000000000000000 #  = 20769187434139310514121985316880384
    END =  0x7ffffffffffffffffffffffffffff # 41538374868278621028243970633760767
    # (2^114...2^115-1) 
    """   
    PubKey00 = 024CF1C3522A04DD725DD93F24BC0BF0CB5D714A6ADEA6C8CFEDCB9298B7BE4696
    PubKey01 = 038E953B34BA2B55166E0B3BE39BE9051CBB002D1DF0B717D841D6B21D78BC9DE9
    """
    PubKey0 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" # 1
    PubKey1 = "039524456E37F332D4C699B35D1701FF9B6F8ABA154D90793B49C7E36BFF4BB0B2" # 1000


    if PubKey0>PubKey1:
        PubKey0,PubKey1 = PubKey1,PubKey0

    # PubKey1 = "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"

    # example input
    # x = "03CF62F121200F56C503DC6CEC1AA862E03B6B85D84D9D4026F093A254D62DC72B" #

    # middle = 0x00000000000030402003000000000000000000, 3822797541106581405631021842432 61086C18209500402100042086807
    target = "0309F53F2B988FE3A34185A626E522D894D785123AD21444F6CC3B094130328DF9"

    target = "0248d313b0398d4923cdca73b8cfa6532b91b96703902fc8b32fd438a3b7cd7f55"
    start = 0x60f4d11574f5deee49961d9609ac6

    target = "02ec38b5ec6342a68e8e96d7839252b3a3f2a9557210f2cce56c4782317428c0f8"
    target = "02C3EB66D1EA5F025285B3CC305424E4C63EB016542DBE274A14E48B208DC48614"
    start = 0x5ffffffffffffffffffffffffffff
    n = getSubtrahend(target, START, END, PubKey0, PubKey1)
    test_it = subtract(target, n)
    print(f"\n Final subtrahend for target {target}, {start:02X},\n in ({START:02X},{END:02X}) \n"
          f" to get into ({START_NEW:02X}-({END_NEW:02X}) is n={n},{n:02X}: \n"
          f" difference Public Key is {test_it}"
          )

