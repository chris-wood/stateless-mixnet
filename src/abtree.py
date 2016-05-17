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

        # p = primes.get_nth_prime(n)
        # 1024-bit prime generated from openssl (see README)
        p = int("D5C21E4246C62176FF0A22637207224972EE1B9D65387383EB1897032472F1F40940448E0FB24CBD791FD89A491000B507CC510345457513189F4A62666F1C03896FBB07A17C75E4BCC7B1289CE252417303E8A537728BFF1D9187261DCD1FD18D1F48953C8526607B657A8B0422BBCFEF1A6F24470FFB23C7DFE1F936E05CFF", 16)
        g = random.randint(0, p)
        k = random.randint(0, p)
        self.params = Params(g, k, p)

        self.root = ABTree(self.params)
        self.levels = { 0: [self.root] }

    def _compute_hash(self, val):
        val = int_digest(val) % self.params.p
        r = random.randint(0, self.params.p)
        return hash(val, r, self.params.g, self.params.gk, self.params.p)

    def _transform_name(self, name):
        segments = name.split("/")[1:]
        merged_segments = []
        for i, toss in enumerate(segments):
            merged = ""
            for j in range(i + 1):
                merged += segments[j]
            merged_segments.append(merged)
        return merged_segments

    @timed
    def add_item(self, name, item):
        name_segments = self._transform_name(name)
        obfuscated_name = map(lambda n : self._compute_hash(n), name_segments)
        levels = self.root.insert(obfuscated_name, (name, item))
        
        for i, level in enumerate(levels):
            if i not in self.levels:
                self.levels[i] = []
            self.levels[i].append(level)

    @timed
    def lookup_name(self, name, start_prefix_length = 0):
        name_segments = self._transform_name(name)
        name = map(lambda n : self._compute_hash(n), name_segments)

        for level in self.levels[start_prefix_length]:
            match = level.lookup(name[start_prefix_length:])
            if match != None:
                return match

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

    def lookup(self, components, start_prefix_length = 0):
        if len(components) == 0:
            return None

        head = components[start_prefix_length]
        match = self.find_match(head)

        if match != None:
            if len(components) > 1:
                return match.lookup(components[(start_prefix_length + 1):], 0)
            else:
                return match.items
        else:
            return None

    def insert(self, components, item):
        head = components[0]
        match = self.find_match(head)

        if match != None:
            levels = [self]
            if len(components) > 1:
                levels.extend(match.insert(components[1:], item))
            else:
                match.insert_item(item)

            return levels
        else:
            child = ABTree(self.params)
            levels = [self]
            if len(components) > 1:
                levels.extend(child.insert(components[1:], item))
            else:
                child.insert_item(item)
            self.entries.append((head, child))
            
            return levels

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

# Read in URIs from the data file
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

# If a file was provided, use that instead
if (len(sys.argv) > 2):
    with open(sys.argv[2], "r") as fh:
        for line in fh:
            line = line.strip()
            names.append(line)

# Insert them
index = 0
for name in names:
    table.add_item(name, 1) # 1 is the item we're adding (link ID in this case)
table.add_item("/b", 2)

# Display the resulting tree
print table.root

# Lookup
for name in names:
    print table.lookup_name(name)
    print table.lookup_name(name, 2)
    print ""
print table.lookup_name("/b")

# Protocol:
# - Two adjacent nodes exchange public keys and group parameters... that's it.
#     -> Don't need to trust neighbor
# - Each router uses a single salt to hash each component of the name
# - Routers use LPM to forward the name one hop ahead (some prefix hashes will match)
#
# Q: what about next-hop neighbors?
