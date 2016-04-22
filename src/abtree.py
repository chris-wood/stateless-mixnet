import sys
import random
import primes
import hashlib
import time

def timed(func):
    def time_decorator(*args, **kw):
        ts = time.time()
        result = func(*args, **kw)
        te = time.time()
        print >> sys.stderr, "%s: %f" % (str(func.__name__), (te - ts))
        return result
    return time_decorator

# String to int
def int_digest(s):
    return int(hashlib.sha1(s).hexdigest(), 16)

# Our "hash" function
def hash(secret, salt, gen, public_key, modulus):
    h1 = pow(public_key, salt, modulus)
    h2 = pow(gen, secret + salt, modulus)
    return (h1, h2)

# Our "compare" function
def compare(hash1, hash2, secret_key, modulus):
    (h11, h12) = hash1
    (h21, h22) = hash2

    p1 = (pow(h12, secret_key, modulus) * h21) % modulus
    p2 = (pow(h22, secret_key, modulus) * h11) % modulus

    return p1 == p2

class Params(object):
    def __init__(self, g, k, p):
        self.g = g
        self.k = k
        self.gk = pow(g, k, p)
        self.p = p

# The "anonymous" tree
class ABTable(object):
    def __init__(self, n):
        self.n = n

        p = primes.get_nth_prime(n)
        g = random.randint(0, p)
        k = random.randint(0, p)
        self.params = Params(g, k, p)

        self.root = ABTree(self.params)

    def _compute_hash(self, val):
        val = int_digest(val) % self.params.p
        r = random.randint(0, self.params.p)
        return hash(val, r, self.params.g, self.params.gk, self.params.p)

    @timed
    def add_item(self, name, item):
        name = map(lambda n : self._compute_hash(n), name.split("/"))
        self.root.insert(name, item)

    @timed
    def lookup_name(self, name):
        name = map(lambda n : self._compute_hash(n), name.split("/"))
        return self.root.lookup(name)

# The "anonymous" tree
class ABTree(object):
    def __init__(self, params):
        self.entries = []
        self.params = params
        self.items = []

    def find_match(self, value):
        for (entry, child) in self.entries:
            if compare(entry, value, self.params.k, self.params.p):
                return child
        return None

    def insert_item(self, item):
        if item not in self.items:
            self.items.append(item)

    def lookup(self, components):
        head = components[0]
        match = self.find_match(head)

        if match != None:
            if len(components) > 1:
                return match.lookup(components[1:])
            else:
                return match.items
        else:
            return None

    def insert(self, components, item):
        head = components[0]
        match = self.find_match(head)

        if match != None:
            if len(components) > 1:
                match.insert(components[1:], item)
            else:
                match.insert_item(item)
        else:
            child = ABTree(self.params)
            if len(components) > 1 :
                child.insert(components[1:], item)
            else: 
                child.insert_item(item)
            self.entries.append((head, child))

    def __tostring__(self, indents = 0):
        s = " -> " + str(self.items) + "\n"
        for (entry, child) in self.entries:
            s += "  " * indents
            s += "%s" % (str(entry))
            s += child.__tostring__(indents + 1)
        return s

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return self.__tostring__(0)

# Choose a random prime
n = int(sys.argv[1])
table = ABTable(n)

# Create some names to insert
names = [
    "/a/b/c/d1",
    "/a/b/c/d2",
    "/a/b/c/d3",
    "/a/b/c1",
    "/a/b/c2",
    "/a/b/c2",
    "/a/b1",
    "/a/b2",
    "/a/b3",
]

# Insert them
for name in names:
    table.add_item(name, 1) # 1 is the item we're adding (link ID in this case)
table.add_item("/b", 2)

# Display the resulting tree
print table.root

# Lookup
for name in names:
    print table.lookup_name(name)
print table.lookup_name("/b")

# Protocol:
# - Two adjacent nodes exchange public keys and group parameters... that's it.
#     -> Don't need to trust neighbor
# - Each router uses a single salt to hash each component of the name
# - Routers use LPM to forward the name one hop ahead (some prefix hashes will match)
#
# Q: what about next-hop neighbors?
