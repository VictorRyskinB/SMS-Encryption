import random as rand
import hashlib
import math



### Publicly agreed EC and points
## NIST p-224
# E : y^2 ≡ x^3 +ax +b mod p,
# p=26959946667150639794667015087019630673557916260026308143510066298881
# n=26959946667150639794667015087019625940457807714424391721682722368061

# a=-3modp
# a=p-3
# a=26959946667150639794667015087019630673557916260026308143510066298878

# b=18958286285566608000408668544493926415504680968679321075787234672564

# Gx=19277929113566293071110308034699488026831934219452440156649784352033
# Gy=19926808758034470970197974370888749184205991990603949537637343198772



##




p=26959946667150639794667015087019630673557916260026308143510066298881
n=26959946667150639794667015087019625940457807714424391721682722368061

#a=-3modp
#a=p-3
a=26959946667150639794667015087019630673557916260026308143510066298878

b=18958286285566608000408668544493926415504680968679321075787234672564

Gx=19277929113566293071110308034699488026831934219452440156649784352033
Gy=19926808758034470970197974370888749184205991990603949537637343198772




#Base point, calculated ahead of time.

Bx=15095627133522154776839792545994843069240014348762964058388900876054

By=12501888384019097225619186215393737256399424287745207321217416764170



##simple curve

# p=11
# n=13
# a=1
# b=6

# Gx=2
# Gy=7

# Bx=2
# By=7










#calculating the amount of bits the hash will have.
Ln=int(math.log2(n))+1





def gcdFunc(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x, y = gcdFunc(b % a, a)
    return gcd, y - (b // a) * x, x

def modInverse(a, m):
    #print(f"a={a}")
    gcd, x, y = gcdFunc(a, m)
    if gcd != 1:
        #incase an inverse doesn't exist, functions that call this one can handle the 0 case.
        return 0
    else:
        return x % m


#functions tests if a point is on our elliptic curve
def onCurve(x,y):
    lhs=pow(y,2,p)
    x3=pow(x,3,p)
    rhs=x3+a*x+b
    lhs=lhs%p
    rhs=rhs%p
    if (lhs==rhs):
        return True
    else:

        return False


#function that adds 2 points as defined by the electic curve group
def ECAdd(x1,y1,x2,y2):
    
    
    if x1 is None:
        return x2,y2
    if x2 is None:
        return x1,y1
    
    
    
    if (x1!=x2):
        #m=(y2-y1)/(x2-x1)
        mdividend=(y2-y1)%p
        mdivisor=(x2-x1)%p
        mdivisor=modInverse(mdivisor,p)
        
        m=(mdividend*mdivisor)%p
        
        x3=pow(m,2)-x1-x2
        y3=m*(x1-x3)-y1
        y3=y3%p
        x3=x3%p
    elif (x1==x2 and y1==((-y2)%p)):
        x3=None
        y3=None
    
    elif (x1==x2 and y1==y2):
        
        # m=((3*pow(x1,2,p)+a)%p)/(2*y1)
        mdividend=(3*pow(x1,2,p)+a)%p
        mdivisor=(2*y1)%p
        mdivisor=modInverse(mdivisor,p)
        
        m=(mdividend*mdivisor)%p
        
        
        
        #x3=pow(m,2,p)-x1-x2
        x3=(m**2)%p-x1-x2
        #print(f"x3={x3}")
        y3=m*(x1-x3)-y1
        
        y3=y3%p
        x3=x3%p
 
    
    return x3,y3





#multiplying a point by a scalar in the electic curve group, uses the double and add algorithm for efficiency
def ECMult(x1,y1,scl):
    x2,y2,= None, None
    scl=int(scl)
    while (scl>0):
        smod=scl%2
        if (smod==1):
            x2,y2=ECAdd(x1, y1, x2, y2)
        x1,y1=ECAdd(x1,y1,x1,y1)
        scl=scl//2
    return x2,y2






#generates a public key based on a received private key
def publicKey(d):
    Qx,Qy=ECMult(Bx,By,d)
    return (Qx,Qy)


#generates a random private key
def privateKey():
    
    d=rand.randint(2, n-1)
    return d


#creates a random key for a new message
def createMsgKey():
    
    
    r=0
    kinv=0
        

    while (r==0):
        while(kinv==0):
            k=rand.randint(2,n-2)%(n-1)
            kinv=modInverse(k,n)
        
        #point on curve
        x1,y1=ECMult(Bx,By,k)
        
        r=x1%n
    return r, k, kinv
    
#hashing the message, and only taking Ln bits from it. 
def hashMsg(msg):
    h=hashlib.sha256(msg.encode())
    h=h.hexdigest()
    e=int(h,16)
    
    
    #sra=shift right amount. i.e removing all the bits that don't fit Ln
    sra=int(math.log2(e))-Ln+1
    z=e>>sra
    
    return z

#signing message using the given private key. 
def signMessage(d,msg):
    
    s=0
    z=hashMsg(msg)
    while (s==0):
        r, k, kinv = createMsgKey()
        s=(kinv*(z+r*d))%n
    return s,r


#verifying signature based on public key, message and messages keys/signatures
def verifySignature(Q,msg, s,r):
    
    Qx,Qy=Q
    
    if not (onCurve(Qx,Qy)):
        return False
    
    
    z=hashMsg(msg)
    c=modInverse(s,n)
    
    
    u1=(z*c)%n
    
    u2=(r*c)%n
    
    x1,y1=ECMult(Bx,By,u1)
    x2,y2=ECMult(Qx,Qy,u2)
   
    
    
    x,y=ECAdd(x1,y1,x2,y2)
    

    
    if (x==None):
        #print("signature invalid")
        return False
    
    
    if (r==(x%n)):
        #print("Signature valid")
        return True
    else: 
        #print("signature invalid")
        return False
    
    
    

####### Test main


## User alice:
#private key d, and public keys A

d=privateKey()
A=publicKey(d)
#message:
Amsg="Hello, this is alice"
#signingmessage
s,r=signMessage(d,Amsg)


## User bob:
print(verifySignature(A,Amsg,s,r))






