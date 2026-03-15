import time

print("Starting memory allocation")
data = []
try:
    while True:
        data.append(bytearray(10 * 1024 * 1024))
        print(f"Allocated {len(data) * 10}MB")
        time.sleep(0.5)
except MemoryError:
    print("Python caught a MemoryError.")