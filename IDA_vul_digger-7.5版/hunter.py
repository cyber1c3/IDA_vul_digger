#encoding:utf-8

from lib import fsb as fsb_c
from lib import strcpy_check as strcpy_c
from lib import read_check as read_c
from lib import dangerous_func as dangerous_c
from lib import uaf_check 


def check_arch():
    '''
        检查当前的x86的指令集架构，返回64 32 16
    '''
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
        return bits
    elif info.is_32bit():
        bits = 32
        return bits
    print("[-] error! not 32 or 64 arch!")
    return 0



if __name__ == '__main__':
    print("[ ==========IDA-python vulnerability hunter========== ]")
    bits = check_arch()
    print('[*] program Arch %d:'%bits,"\n")

    print("[*] check for all dangeroust function:")
    dangerous_c.check_danger()
    print("[*] finish check dangerous function\n")



    print('[*] start check format strings bugs...')
    fsb_c.fsb_check(bits)
    print('[*] finish check format strings bugs\n')

    if bits==64:
        print('[*] start check read func...')
        read_c.read_check_64()
        print('[*] finish check read func\n')

        print('[*] start check strcpy func...')
        strcpy_c.strcpy_check_64()
        print('[*] finish check strcpy func\n')

    if bits==32:
        print('[*] start check read func...')
        read_c.read_check_32()
        print('[*] finish check read func\n')

        print('[*] start check strcpy func...')
        strcpy_c.strcpy_check_32()
        print('[*] finish check strcpy func\n')