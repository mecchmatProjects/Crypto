import numpy as np
import subprocess
import time

FNAME = "iterdata.txt"
FNAME_BIN = "iterdata.dat"


# Define the start and end of the key space range in hexadecimal format
start = int('20000000000000000', 16)
end = int('3ffffffffffffffff', 16)

# Define the difference between consecutive key spaces in hexadecimal format
difference = int('00000fffffffffff', 16)

print(start, end,difference, difference*4/1024/1024/1024)

"""
   create text file from the given range
   
"""
def create_text_file(fname, start, end):
    a = np.arange(start,end)
    np.savetxt(fname, a,fmt="%16x",delimiter=' ')

def create_bin_file(fname, start, end):
    
    #np.save(fname,a)
    fp = np.memmap(fname, dtype=np.uint32, mode='w+', shape=(end-start,))
    a = np.arange(1,end-start+1,dtype=np.uint32)
    fp[:] = a[:]
    fp.flush()


def iterate_file(fname,start, end):
    difference =  end - start
    fp = np.memmap(fname, dtype=np.int64, mode='readwrite', shape=(difference,))
    a = np.arange(0,difference,dtype=np.int64)
    fp[:] = a[:]
    #fp.flush()
    #data = np.memmap(fname, dtype=np.uint32, mode='r+',shape=(1000000,))
    for _ in range(100):
        rand_num = int((np.random.randint(0,difference,dtype=np.int32)) )
        # print(rand_num)
        # data = np.load(fname, mmap_mode='r+',allow_pickle=True)
        elem = start + fp[rand_num]

        res = "".join(("%x".format(elem),"0000000"))        
        yield res
        np.delete(fp, rand_num)


    fp.flush() 
        


if __name__ == "__main__":
    #create_text_file(FNAME,start,start+1000000)
    #create_bin_file(FNAME_BIN,start,start+1000000)

    for x in iterate_file(FNAME_BIN,start,start +(difference>>15)):
        print("x=",x)
