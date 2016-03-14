import sys
import random

# Sieve of Eratosthenes
# Code by David Eppstein, UC Irvine, 28 Feb 2002
# http://code.activestate.com/recipes/117119/
def gen_primes(n):
    """ Generate an infinite sequence of prime numbers.
    """
    # Maps composites to primes witnessing their compositeness.
    # This is memory efficient, as the sieve is not "run forward"
    # indefinitely, but only as long as required by the current
    # number being tested.
    #
    D = {}

    # The running integer that's checked for primeness
    q = 2
    count = 0
    while count < n:
        if q not in D:
            # q is a new prime.
            # Yield it and mark its first multiple that isn't
            # already marked in previous iterations
            #
            yield q
            D[q * q] = [q]
            count += 1
        else:
            # q is composite. D[q] is the list of primes that
            # divide it. Since we've reached q, we no longer
            # need it in the map, but we'll mark the next
            # multiples of its witnesses to prepare for larger
            # numbers
            #
            for p in D[q]:
                D.setdefault(p + q, []).append(p)
            del D[q]

        q += 1

n = int(sys.argv[1]) #nth prime
primes = [p for p in gen_primes(n)]
p = primes[-1]

# Pick a generator
g = random.randint(0, p)

# Compute k and public key 
k = random.randint(0, p)
gk = pow(g, k, p)

# Our "hash" function
def hash(secret, salt, gen, public_key):
    h1 = pow(public_key, salt, p)
    h2 = pow(gen, secret + salt, p)
    return (h1, h2)

# Generate the secret and salts
secret = random.randint(0, p)
r = random.randint(0, p)
s = random.randint(0, p)

# Generate the hashes
h1 = hash(secret, r, g, gk)
h2 = hash(secret, s, g, gk)

# Our "compare" function
def compare(hash1, hash2, secret_key, public_key):
    (h11, h12) = hash1
    (h21, h22) = hash2

    p1 = (pow(h12, k, p) * h21) % p
    p2 = (pow(h22, k, p) * h11) % p

    return p1 == p2

equal = compare(h1, h2, k, gk)
print "%s == %s? %s" % (str(h1), str(h2), equal)

# Protocol:
# - Two adjacent nodes exchange public keys and group parameters... that's it.
#     -> Don't need to trust neighbor
# - Each router uses a single salt to hash each component of the name
# - Routers use LPM to forward the name one hop ahead (some prefix hashes will match)
#
# Q: what about next-hop neighbors?
