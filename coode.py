import numpy as np
import subprocess
import time

# Define the start and end of the key space range in hexadecimal format
start = int('20000000000000000', 16)
end = int('3ffffffffffffffff', 16)

# Define the difference between consecutive key spaces in hexadecimal format
difference = int('00000fffffffffff', 16)

# Create an empty set to store the ranges that have already been generated
generated_ranges = set()

# Define a function to generate a random key space
def generate_key_space():
    while True:
        # Generate a random number within the first 26 bits of the key space range using NumPy
        rand_num = np.random.randint(start >> 40, end >> 40, dtype=int) << 40

        # Calculate the end position for the current key space
        rand_end = rand_num + difference

        # Check if the current key space overlaps with any of the previously generated ranges
        overlap = False
        for prev_start, prev_end in generated_ranges:
            if prev_start <= rand_num <= prev_end or prev_start <= rand_end <= prev_end:
                overlap = True
                break

        # If the current key space does not overlap with any of the previously generated ranges, return it
        if not overlap:
            generated_ranges.add((rand_num, rand_end))
            return (rand_num, rand_end)


            
# Define the command to run internal_tool.exe with the random key space
def run_internal_tool(key_space):
    command = f"internal_tool.exe -b 160 -t 256 -p 1024 --keyspace {hex(key_space[0])}:{hex(key_space[1])} 1PPC6iTr4gvXMdLe8hCexJ4tgqe7qnLxp9 "
    subprocess.run(command, shell=True)

# Define a function to write the key space to a file
def write_range_to_file(key_space):
    with open('ranges_searched.txt', 'a') as f:
        f.write(f"{hex(key_space[0])}:{hex(key_space[1])}\n")

# Generate and run random key spaces until the search string is found
while True:
    key_space = generate_key_space()
    print(f"Key space: {hex(key_space[0])} - {hex(key_space[1])}")
    write_range_to_file(key_space)  # Write the key space to the file
    run_internal_tool(key_space)
    time.sleep(3)  # Wait for 3 seconds before generating the next key space
    # Check if the search string is found in the output of the last run of internal_tool.exe
    result = subprocess.run('type output.txt | find "1PPC6iTr4gvXMdLe8hCexJ4tgqe7qnLxp9  "', shell=True, capture_output=True)
    if result.returncode == 0:
        print('Search string found!')
        break    
