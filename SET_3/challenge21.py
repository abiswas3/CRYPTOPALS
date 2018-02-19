import sys
sys.path.append('../')

from twister import mersenne_rng

if __name__ == "__main__":
    
    rng = mersenne_rng(1131464071)
    for i in range(10):
        print(rng.get_random_number())
