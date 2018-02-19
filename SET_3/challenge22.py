import sys
sys.path.append('../')

from Crypto.Random import random
from twister import mersenne_rng
import challenge21
import time

# Generate some random seed based on time
t = int(time.time())

# Add a random number to it with a relatively small range
# this is now your seed
t += random.randint(40, 1000)
seed = int(t)
print("Seed", seed)

# Using that seed generate a random number
rng = mersenne_rng(seed)
x = rng.get_random_number()
print("Radom number", x)

# Now we start relatively close to the seed
# and brute force it.
t += random.randint(40, 1000)

# Since we know that given the same seed the first output is always
# the same: if we get the same random number we've figured out the
# seed
for i in range(2000):
    k = t - i
    rng2 = mersenne_rng(k)
    y = rng2.get_random_number()
    
    if x == y:
        print("The seed you used was: ", k)
        
