import struct, hashlib, hmac

# ---------- ChaCha20 (RFC 8439) ----------
def rotl(x,n): return ((x<<n)|(x>>(32-n)))&0xffffffff
def qr(s,a,b,c,d):
    s[a]=(s[a]+s[b])&0xffffffff; s[d]=rotl(s[d]^s[a],16)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]=rotl(s[b]^s[c],12)
    s[a]=(s[a]+s[b])&0xffffffff; s[d]=rotl(s[d]^s[a],8)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]=rotl(s[b]^s[c],7)
def block(key,counter,nonce):
    c=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
    k=list(struct.unpack('<8I',key))
    n=list(struct.unpack('<3I',nonce))
    st=c+k+[counter&0xffffffff]+n
    w=st[:]
    for _ in range(10):
        qr(w,0,4,8,12);qr(w,1,5,9,13);qr(w,2,6,10,14);qr(w,3,7,11,15)
        qr(w,0,5,10,15);qr(w,1,6,11,12);qr(w,2,7,8,13);qr(w,3,4,9,14)
    out=[(w[i]+st[i])&0xffffffff for i in range(16)]
    return struct.pack('<16I',*out)
def chacha20(key,nonce,data,counter=1):
    out=bytearray()
    for i in range(0,len(data),64):
        ks=block(key,counter+i//64,nonce)
        chunk=data[i:i+64]
        out+=bytes(a^b for a,b in zip(chunk,ks))
    return bytes(out)

# RFC 8439 2.3.2 block KAT
key=bytes(range(32))
nonce=bytes.fromhex('000000090000004a00000000')
ks=block(key,1,nonce)
exp='10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e'
print('chacha block KAT :', 'OK' if ks.hex()==exp else 'MISMATCH', ks.hex())

# RFC 8439 2.4.2 encryption vector -> emit ciphertext
pt=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
nonce2=bytes.fromhex('000000000000004a00000000')
ct=chacha20(key,nonce2,pt,counter=1)
print('chacha sunscreen ct:', ct.hex())

# ---------- HMAC-DRBG (SP 800-90A) ----------
class HmacDrbg:
    def __init__(self,entropy,nonce,perso=b'',halg=hashlib.sha512):
        self.h=halg; self.outlen=halg().digest_size
        self.K=b'\x00'*self.outlen; self.V=b'\x01'*self.outlen
        self._update(entropy+nonce+perso)
    def _hmac(self,k,m): return hmac.new(k,m,self.h).digest()
    def _update(self,provided):
        self.K=self._hmac(self.K,self.V+b'\x00'+(provided or b''))
        self.V=self._hmac(self.K,self.V)
        if provided is not None:
            self.K=self._hmac(self.K,self.V+b'\x01'+provided)
            self.V=self._hmac(self.K,self.V)
    def generate(self,n,add=None):
        if add is not None: self._update(add)
        out=b''
        while len(out)<n:
            self.V=self._hmac(self.K,self.V); out+=self.V
        self._update(add)
        return out[:n]

# NIST CAVP HMAC_DRBG, SHA-256, no reseed, no PR, Count 0 (generate twice, return 2nd)
ei=bytes.fromhex('ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488')
no=bytes.fromhex('659ba96c601dc69fc902940805ec0ca8')
d=HmacDrbg(ei,no,halg=hashlib.sha256)
d.generate(128)             # first call, discarded
rb=d.generate(128)          # returned bits
print('drbg sha256 NIST rb:', rb.hex())

# SHA-512 DRBG vector for natrium's default hash (single generate, 64 bytes)
ei2=bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
no2=bytes.fromhex('202122232425262728292a2b2c2d2e2f')
d2=HmacDrbg(ei2,no2,halg=hashlib.sha512)
print('drbg sha512 vec    :', d2.generate(64).hex())
