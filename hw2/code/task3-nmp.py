from multiprocessing import Pool
import random


if __name__=='__main__':
    NPROC = 6 #Numer of available processors
    p = Pool(NPROC)

    rand_list = []
    n = 10000000
    for i in range(n):
        rand_list.append(random.randint(1,10000))
    print(f"start {len(rand_list)}")
    result = 0
    for i in rand_list:
        result += i
    
    print(result)