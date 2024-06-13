from pwn import *
context.log_level = 'debug'
context.arch = "amd64"
r = remote('20.195.26.61', 1337)
def find_fraction_digit(a, b, k):
    remainder = a % b
    seen_remainders = {}  # Dùng để theo dõi các phần dư đã xuất hiện

    for i in range(k):
        remainder *= 10
        digit = remainder // b
        remainder = remainder % b

        # Nếu phần dư đã xuất hiện trước đó, chứng tỏ phân số là số hữu hạn
        if remainder in seen_remainders:
            return digit

        seen_remainders[remainder] = i  # Lưu trữ vị trí của phần dư

    return digit

r.recvuntil(b'WELCOME TO ASCIS 2023 - PROGRAMING CHALLENGE\n')

while(1):
    arr = (r.recvline().strip()).split(b" ")
    # print(arr)
    a = int(arr[0],10)
    b = int(arr[1],10)
    k = int(arr[2],10)
    # print(arr)
    # Find and print the kth digit
    digit = find_fraction_digit(a, b, k)
    # print(f"The {k}th digit after the decimal point in {a}/{b} is: {digit}")
    r.sendline(str(digit))
    time.sleep(0.5)
r.interactive()
