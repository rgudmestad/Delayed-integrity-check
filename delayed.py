import hmac     # This module implements the HMAC algorithm as described by RFC 2104.
import hashlib  # This module implements a common interface to many different secure hash and message digest algorithms. Included are the FIPS secure hash algorithms
                # SHA1, SHA224, SHA256, SHA384, and SHA512 (defined in FIPS 180-2) as well as RSA’s MD5 algorithm (defined in Internet RFC 1321).  
                # The terms “secure hash” and “message digest” are interchangeable. Older algorithms were called message digests. The modern term is secure hash.


m = hmac.new(b'test', b'', hashlib.sha256,)
m2 = hmac.new(b'test', b'', hashlib.sha256,)
messages = ["Mitt ","navn ","er ","Racin ","Gudmestad "]
string = "Mitt navn er Racin Gudmestad "
for i in range(len(messages)):
    m.update(messages[i].encode("UTF-8"))
    
m2.update(string.encode("UTF-8"))
if hmac.compare_digest(m.hexdigest(), m2.hexdigest()):
    print("Match")
else:
    print("no Match")

print(m.hexdigest())