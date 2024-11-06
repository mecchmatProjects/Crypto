
from decimal import *
print(getcontext())

myothercontext = Context(prec=90, rounding=ROUND_HALF_DOWN)
setcontext(myothercontext)
"""
a =
1.5931220318142209081847200718800513284478983895232845771598115094865772293425176551
147041
b =
1.4180958678849065567601929430299366804279726526182465238391256914846175095759022850
508064
c= 1/(1-1/a) =
2.6859936848766770740741701602124664887178336154356167143236626569580529789903079049
227949;
d= 1/(1-1/b) =
3.3917959415836179238295055450635509297663016085355811568226926449910165645921925937
776673

X = 
1.0577521107344690689776559494462551710425873710178916741468675224655304928971691416
194016
Y = 
1.0620856754761767296035627965830625588427258964162073399765133221582944511313024665
654142

"""

A = Decimal('1.5931220318142209081847200718800513284478983895232845771598115094865772293425176551147041')
print(A)
B = Decimal('1.4180958678849065567601929430299366804279726526182465238391256914846175095759022850508064')
print(B)

C = Decimal('2.6859936848766770740741701602124664887178336154356167143236626569580529789903079049227949')
print(C)
D = Decimal('3.3917959415836179238295055450635509297663016085355811568226926449910165645921925937776673')
print(D)

H = C/(1/(A-B)/(A*B))
print(H)

CD = A/B
print(CD)

X = Decimal('1.0577521107344690689776559494462551710425873710178916741468675224655304928971691416194016')
print(X)
Y = Decimal('1.0620856754761767296035627965830625588427258964162073399765133221582944511313024665654142')
print(Y)
Z = Y-H
print(Z)

Y1 = 1/D
print(Y1, 1-Y1)
Y2 = (C-1)/C
print(Y2)

print(X/A)
print(Y/A)

print(A+C)
print((A+C)/C)

X3 = (A+C)/(B+D)
Y3 = D/C
print(X3/X,Y3/X)
print(X3*Y3, CD)



def farey(x, N):
    a, b = 0, 1
    c, d = 1, 1
    while (b <= N and d <= N):
        mediant = (a+c)/(b+d)
        if x == mediant:
            if b + d <= N:
                return a+c, b+d
            elif d > b:
                return c, d
            else:
                return a, b
        elif x > mediant:
            a, b = a+c, b+d
        else:
            c, d = a+c, b+d

    if (b > N):
        return c, d
    else:
        return a, b


"""
p = 4
N = p**16
p2= p//2
for i in range(N):
    i1 = i % p - p2+1
    i2 = (i//p) % p - p2+1
    i3 = (i // p**2) % p- p2+1
    i4 = (i // p**3) % p - p2+1
    i5 = (i // p**4) % p - p2+1
    i6 = (i // p**5) % p -p2+1
    i7= (i // p**6) % p -p2+1
    i8= (i // p**7) % p -p2+1
    i9 = (i // p ** 8) % p - p2+1
    i10 = (i // p ** 9) % p - p2+1

    i11 = (i // p ** 10) % p - p2+1
    i12 = (i // p ** 11) % p - p2+1
    i13 = (i // p ** 12) % p - p2+1
    i14 = (i // p ** 13) % p - p2+1
    i15 = (i // p ** 14) % p - p2+1
    i16 = (i // p ** 15) % p - p2+1


    # X3 = A**i1*(C**i2)*B**i3*D**i4*(A-1)**i7/(B+D)**i5/(A+C)**i6/(B-1)**i8 * (C-1)**i9 * (D-1)**i10

    X4 = (Decimal(i1)*(A + C)*(C-1) + Decimal(i2)*C**2 + Decimal(i3)*C**2*(C-1)*(A-1) + Decimal(i4)*C*(C-1))*C**i6*(C-1)**i7
    if X4==0:
        continue
    if i5==0:
        X4 = 1
    elif i5 == -1:
        X4 = 1/X4
    elif i5==2:
        X4= X4*X4

    if i1+i2+i3+i4<=0:
        continue
    X4 = X4*Decimal(i1+i2+i3+i4)**i8

    X5 = (i9 * (B + D) * (D - 1) + i10 * D ** 2 + i11 * D ** 2 * (D - 1) * (B - 1) + i12 * D * (
                D - 1)) * D ** i14 * (D - 1) ** i15

    if X5==0:
        continue
    if i10 + i11 + i12 + i9 <= 0:
        continue

    if i13==0:
        X5 = 1
    elif i5 == -1:
        X5 = 1/X5
    elif i5==2:
        X5= X5*X5

    X5 = Decimal(X5)**i13
    X5 = X5*Decimal(i10 + i11 + i12 + i9)**i16

    X3 = X4*X5
    print(X3)
    if abs(X3-X) < 0.00000001 or abs(X3-Y)<0.000001:
        print("OOOOO")
        print(X)
        print(Y)
        print(i1,i2,i3,i4,i5,i6)
        input()

"""
p = 3
k = 15
ind = [0 for _ in range(k)]
N = p**k
p2 = p//2
for i in range(N):

    for j in range(k):
        ind[j] = (i // p**j) % p - p2

    XX = (ind[0] + ind[1]*A + ind[2]*B + ind[3]*C + ind[4]*D)
    if (ind[5] + ind[6]*A + ind[7]*B + ind[8]*C + ind[9]*D)!=0:
        XX = XX * (ind[5] + ind[6]*A + ind[7]*B + ind[8]*C + ind[9]*D)

    if (ind[10] + ind[11] * A + ind[12] * B + ind[13] * C + ind[14] * D)!=0:
        XX /= (ind[10] + ind[11]*A + ind[12]*B + ind[13]*C + ind[14]*D)
    """
    if (ind[15] + ind[16]*A + ind[17]*B + ind[18]*C + ind[19]*D)!=0:
          XX = XX * (ind[15] + ind[16]*A + ind[17]*B + ind[18]*C + ind[19]*D)
    """
    if XX <= 0:
        continue
    check_nom = [Decimal('1') , A+C, C, (A-1),D,(D-1)]
    check_den = [Decimal('1'), B + D, D, (C - 1), C, (B - 1)]

    for nom in check_nom:
        for den in check_den:
            ZZ = XX * nom/den
            if abs(ZZ - X) < 0.000000001 or abs(ZZ - Y) < 0.000000001:
                print("OOOOO")
                print(X)
                print(Y)
                print(ZZ)
                print(nom)
                print(den)

                for m in range(k):
                    print(ind[m],end=",")

                input()