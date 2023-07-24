import math

p = 29  # Prime modulus
base = 2  # Base
target = 21  # Target value

for b in range(1, p):
    
    #if pow(base, b, p) == target:
    if base**b % p == target:
        print("b =", b)
        break



base = 2
target = 21
modulus = 29

from math import ceil, sqrt


def bsgs(g, h, p):
    '''
    Solve for x in h = g^x mod p given a prime p.
    If p is not prime, you shouldn't use BSGS anyway.
    '''
    N = ceil(sqrt(p - 1))  # phi(p) is p-1 if p is prime

    # Store hashmap of g^{1...m} (mod p). Baby step.
    tbl = {pow(g, i, p): i for i in range(N)}

    # Precompute via Fermat's Little Theorem
    c = pow(g, N * (p - 2), p)

    # Search for an equivalence in the table. Giant step.
    for j in range(N):
        y = (h * pow(c, j, p)) % p
        if y in tbl:
            return j * N + tbl[y]

    # Solution not found
    return None


print(bsgs(2, 21, 29))

for x in range(11):
    for y in range(11):
        if (y**2) %11 == (x**3 + 2*x+7) % 11:
            print(x,y)


