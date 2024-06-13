from pwn import *

lis =[-871222578553387942,-3456440840989770153,368,360,-6917285895965957581,2096695603964784419,352,344,4501421280245125089,-5989732096912246845,336,328,-7641474145812966946,5943263215614115999,320,312,3346881274156629838,-4046563652848771978,304,296,1600213061547397258,-7907006450299616387,288,280,2641250925692849876,5764027888120773659,272,264,-2708211178971868809,-1437889653997315907,256,248,-1790267167538066993,6751799815650390725,240,232,-7155949167227380485,-240513889820188763,224,216,8430573516374475283,7014569824855873983,208,200,-1194317526320485479,-2635243135622213470,192,184,3816607778456458796,7739645478794557909,176,168,2239858223738625365,6262919446888351940,160,152,5359968574739497219,-5945185636638990574,144,136,4289602485438450409,-4136753309120802266,128,120,3689636007142570038,7149575679097845041,400,392,3544442000607754086,58494055442021,390,382,-6712584965997026559,5818345077617353901,464,456,-1172694937141806812,-4970398359911696349,448,440,-7528756344694355204,-880185776627970324,432,424,-4294,0,416,408]
bytes_str=[b"\x00"]*1000

rbp_464=b""
for i in range(0, len(lis),4):
    bytes_str[lis[i+2]]=p64(lis[i]&0xffffffffffffffff)
    bytes_str[lis[i+3]]=p64(lis[i+1]&0xffffffffffffffff)


for i in range(len(bytes_str)-1,0,-1):
    if(i==392): 
        break
    if(bytes_str[i] != b"\x00"):
        print("rbp-"+str(i), end = " " )
        print(hex(u64(bytes_str[i])))
        # print(bytes_str[i])
        rbp_464+=bytes_str[i]
    
rbp_464+= p16(u64(bytes_str[392])&0xffff)
print("rbp-"+str(392), end = " " )
print(hex(u64(bytes_str[392])&0xffff))
# print(rbp_464)
for i in range(390,0,-1):

    if(bytes_str[i] != b"\x00"):
        print("rbp-"+str(i), end = " " )
        print(hex(u64(bytes_str[i])))
        # print(bytes_str[i])
        rbp_464+=bytes_str[i]
    if(i==374):
        rbp_464+=b"\x00"*(6)
        print("rbp-"+str(374), end = " ")
        print(hex(0))
        
print(rbp_464)          
        

def shr(val, r_bits, max_bits):
    k = bin(val)[2:].rjust(max_bits, '0')
    k = k[:(max_bits - r_bits)]
    return int(k, 2)

def sar(val, r_bits, max_bits):
    k = bin(val)[2:].rjust(max_bits, '0')
    k = k[(max_bits-r_bits):] + k[:(max_bits-r_bits)]
    return int(k, 2)

def shl(val, r_bits, max_bits):
    k = bin(val)[2:].rjust(max_bits, '0')
    k = k = k[r_bits:] + '0' * r_bits
    return int(k, 2)

def sal(val, r_bits, max_bits):
    if val < 0:
        k = bin(val)[3:].rjust(max_bits, '0')
        k = k[r_bits:] + k[:r_bits]
        return -int(k, 2)
    else:
        k = bin(val)[2:].rjust(max_bits, '0')
        k = k[r_bits:] + k[:r_bits]
        return int(k, 2)


li = ['a2', 'd8', '1b', '89', 'c9', '1e', 'a3', '01', '50', 'be', 'ea', '05', '6c', '06', '64', 'ad', 'ef', 'b9', 'c0', '2a', 'f9', 'c3', '79', '24', 'bb', '05', '99', '06', 'a5', '47', '78', '23', '97', '84', '7b', 'fe', '5a', '06', '4a', 'fc', 'f3', 'c8', 'f3', 'b3', '17', 'bd', '0e', 'ec', '00', '00', '00', '00', '00', '00', 'ef', '3a', '33', '34', '38', '66', '64', '39', '38', '36', '63', '38', '65', '33', '37', '66', '35', '65', '66', '65', '31', '30', '63', '38', '65', '33', '37', '66', '00', '00', '00', '00', '00', '00', '00', '00', '35', '33', '35', '65', '66', '65', 'f3', 'e8', 'cb', 'ae', '45', '06', '84', '5a', 'd0', '08', '41', '5e', '3d', 'a6', 'fe', '57', 'a0', '00', 'dd', '20', '81', '21', '22', '33', '1d', '18', 'f5', '8b', '04', '71', 'af', '23', '3e', '78', '42', 'ce', '09', '65', '0f', 'e1', 'ac', 'e0', '32', '64', '8f', 'ca', '37', 'c3', '95', 'f4', '07', 'c0', '2a', '7c', '91', 'de', '52', '7a', 'b6', '67', 'e5', '53', '40', '9f', '2e', '72', '82', 'c9', '4b', '83', '3f', '4e', 'c7', 'd7', 'b7', 'cc', '1e', 'f1', '1c', '76', '16', '35', '19', '4d', '1a', '79', '10', '8a', '92', '44', 'ab', '86', 'cd', '2b', '43', '7d', '24', 'a7', '9b', 'b9', '14', '98', '0e', 'd4', '4f', 'fd', 'f0', 'd3', '3a', 'e2', '3c', '1b', 'da', '6a', '80', '48', '0c', 'a3', 'd1', '77', 'ec', '0b', '96', 'fa', '5b', '47', 'd8', 'bd', 'e7', '27', 'b1', '7f', '11', 'd9', '49', 'cf', '5d', 'b3', '36', '28', 'e6', '63', 'b2', 'c5', '9c', 'b0', 'f6', '25', '70', 'a8', 'dc', 'fb', 'fc', 'a9', '85', 'e4', '39', 'b8', '5f', 'a5', '74', 'ff', '69', 'f2', '30', '51', '02', '13', '61', '58', 'c2', '17', '46', 'b5', '59', 'bf', 'ef', '6c', 'ee', '89', '9e', 'a4', 'eb', '99', 'db', '6d', 'bc', '54', '8c', '73', '90', 'a2', '34', 'f7', '50', '8d', 'a1', 'e3', 'd6', '2c', '6b', '68', 'be', '8e', '7b', '01', 'f9', 'd5', '1f', '15', '93', '2f', 'ed', '2d', '9d', '55', '56', 'ea', '5c', '0d', 'f8', 'aa', '88', 'c4', '4a', '62', '6f', '05', '38', '9a', 'c1', '03', 'ad', '7e', '75', '29', '94', '60', 'df', '12', '3b', '87', 'ba', 'bb', 'b4', '31', '0a', 'e9', 'c6', '97', '4c', 'c8', '66', '6e', 'd2', '26']
li = [int(i, 16) for i in li]
print(li)

rbp = 464
for i in range(49):
    for ch in range(ord('0'), 128):
        a = i * 715827883
        a = shr(a, 32, 64)
        a = sar(a, 2, 32)
        b = sar(i, 31, 32)
        a -= b
        c = a * 3
        c = sal(c, 3, 32)
        i = (i - c) & 0xff
        
        if i & 1 == 0:
            li[rbp - 400 + i] = ~li[rbp - 400 + i] & 0xff
        li[rbp - 400 + i] ^= li[rbp - 368 + ch]
        
        if li[rbp - 368 + li[rbp - 400 + i]] & 1 == 0:
            li[rbp - 368 + li[rbp - 400 + i]] ^= 66
        li[rbp - 368 + li[rbp - 400 + i]] = ~li[rbp - 368 + li[rbp - 400 + i]] & 0xff

        if li[li[rbp - 368 + li[rbp - 400 + i]]] == li[rbp - 368 + li[rbp - 400 + i]]:
            print(chr(ch), end = ' ')
            break