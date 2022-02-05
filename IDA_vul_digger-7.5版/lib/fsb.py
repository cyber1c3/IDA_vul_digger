#encoding:utf-8

# date: 2019-03-05
# author: thinkycx
# info: This is a baby IDA Python script aims at finding format string vulnerability automatically.
# References: 
#           1. https://cartermgj.github.io/2017/10/10/ida-python/
#           2. IDA Python 初学者指南  作者：Alexander Hanel 翻译:foyjog
# usage:
#           1. shift+F2 and import this script
#           2. Run...
#
# Detect case:

'''
x64:
    vulnerable case 1:                              # 检测前5条指令中是否存在mov rdi，并且参数是否是寄存器
        lea     rax, [rbp+buf]
        mov     rdi, rax        ; format
        mov     eax, 0
        call    _printf
    vulnerable case 2:                              # 同上
        mov     rax, [rbp+buf]
        mov     rdi, rax        ; format
        mov     eax, 0
        call    _printf 
    not vulnerable case 1:                          # 白名单情况，mov edi，offset format
        lea     rax, [rbp+buf]
        mov     rsi, rax
        mov     edi, offset format ; "%s"
        mov     eax, 0
        call    _printf

x86:
    vulnerable case 1:                              # 检测 前一条push指令的操作数是否是 idaapi.o_reg
        lea     eax, [ebp+buf]
        push    eax             ; format
        call    _printf 
    vulerable case 2:                               # 检测 前一条push指令的操作数是否是 o_displ             
        sub     esp, 0Ch
        push    [ebp+buf]       ; format
        call    _printf
    not vulerable case 1:                           # 白名单情况，push offset 
        add     esp, 10h
        sub     esp, 8
        lea     eax, [ebp+buf]
        push    eax
        push    offset format   ; "%s"
        call    _printf


'''
import idc
import idaapi
import idautils

def get_printf_plt():
    '''
        获取printf的plt的地址
    '''
    printf_func=[]
    printf_plt=0
    for func in idautils.Functions():                               # 获取当前程序所有的函数
        # print hex(func), idc.get_func_name(func) 
        if '.printf' in idc.get_func_name(func) or 'printf' in idc.get_func_name(func):                  # 获取printf plt的地址                
            printf_plt = func
            return printf_plt
        if 'printf' in idc.get_func_name(func):
            printf_func.append(func)
    if printf_plt==0:
        print ("[-]there is no printf@plt func")
        return None
    if len(printf_func)>1:
        print ("[+]there are many *printf* func:")
        for x in printf_func:
            print ("0x%x -> %s".format(x,idc.get_func_name(x)))
        
        
def get_scanf_plt():
    '''
        获取scanf的plt的地址
    '''
    for func in idautils.Functions():                               # 获取当前程序所有的函数
        # print hex(func), idc.get_func_name(func) 
        if 'isoc99_scanf' in idc.get_func_name(func) or 'isoc99_scanf' in idc.get_func_name(func):                  # 获取scanf的plt的地址               
            printf_plt = func
            return printf_plt
    print ("[-]there is no isoc99_scanf@plt func")
    return None
    
def find_printf_fsb(printf_plt, bits):      
    ## x64 mov rdi, rax  , 不是offet xxxx
    # find printf plt xrefs;
    # search prev number
    number = 5                                                      # 向前搜索的指令数
    printf_plt_xrefs = list(idautils.XrefsTo(printf_plt, flags=0))  # 交叉引用获取所有.printf的引用
    print ('[+] find printf@plt xref number: ', len(printf_plt_xrefs))
    for xref in printf_plt_xrefs:                                   # 遍历所有的call printf
        print ('[+] call printf addr:', hex(xref.frm))                # 
        now_addr = xref.frm                                         # 获取call printf的地址
        if bits == 64: 
            for i in range(0, number):
                now_addr = idc.prev_head(now_addr)                       # 获取前一条指令
                # print idc.GetDisasm(now_addr)                         # 获取当前地址的反汇编代码
                if idc.print_insn_mnem(now_addr) == 'mov':                      # 向前寻找到mov指令          
                    if idc.print_operand(now_addr, 0) in ['rdi','edi']:       # 判断arg0是否是rdi或edi
                        if idc.print_operand(now_addr, 1) in ['offset']:      # 白名单,有offset就退出
                            break

                        if idc.get_operand_type(now_addr, 1) == idaapi.o_reg:         # 检查操作数2类似是否是寄存器，如果是，可能存在格式化字符串漏洞。
                            print ("[!] Might be a format string vulnerablity : 0x%x %s [WARNING!]" % (now_addr,\
                                 idc.GetDisasm(now_addr)))
                            break


        elif bits == 32:
            for i in range(0, number):
                now_addr = idc.prev_head(now_addr)                           # 检查前一条指令 是否是push
                # print idc.GetDisasm(now_addr)
                if idc.print_insn_mnem(now_addr) in ("jmp","call","ret","retn"):
                    break


                if (idc.print_insn_mnem(now_addr) == 'push' ):
                    if  'offset' in idc.print_operand(now_addr, 0) :             # 白名单，push的是一个变量
                        break

                    elif idc.get_operand_type(now_addr, 0) in [ idaapi.o_reg, idaapi.o_displ]:
                        # if 'ebp' in idc.print_operand(now_addr, 0):
                        #     break
                        print ("[!] Might be a format string vulnerablity : 0x%x %s [WARNING!]" % (now_addr,\
                                     idc.GetDisasm(now_addr)))
                        break
                if (idc.print_insn_mnem(now_addr) == 'mov' )and ('esp' in idc.print_operand(now_addr, 0)):
                    if idc.get_operand_type(now_addr, 1) in [ idaapi.o_reg, idaapi.o_displ ]:
                        print ("[!] Might be a format string vulnerablity : 0x%x %s [WARNING!]" % (now_addr,\
                                     idc.GetDisasm(now_addr)))
                    break



def find_scanf_fsb(scanf_plt, bits):      

    number = 5                                                      # 向前搜索的指令数
    scanf_plt_xrefs = list(idautils.XrefsTo(scanf_plt, flags=0))  # 交叉引用获取所有.scanf
    print ('[+] find scanf@plt xref number: ', len(scanf_plt_xrefs))
    for xref in scanf_plt_xrefs:                                   # 遍历所有的call scanf
        print ('[+] call scanf addr:', hex(xref.frm))               # 
        now_addr = xref.frm                                         # 获取call scanf的地址
        if bits == 64: 
            for i in range(0, number):
                now_addr = idc.prev_head(now_addr)                       # 获取前一条指令
                # print idc.GetDisasm(now_addr)                         # 获取当前地址的反汇编代码
                if idc.print_insn_mnem(now_addr) == 'mov':                      # 向前寻找到mov指令          
                    if idc.print_operand(now_addr, 0) in ['rdi','edi']:       # 判断arg0是否是rdi或edi
                        if idc.print_operand(now_addr, 1) in ['offset']:      # 白名单,有offset就退出
                            pass
                        if idc.get_operand_type(now_addr, 1) == idaapi.o_reg:         # 检查操作数2类似是否是寄存器，如果是，可能存在格式化字符串漏洞。
                            print ("[!] Might be a format string vulnerablity : 0x%x %s [WARNING!]" % (now_addr,\
                                 idc.GetDisasm(now_addr)))
        elif bits == 32:
            for i in range(0, number):
                now_addr = idc.prev_head(now_addr)
                if idc.print_insn_mnem(now_addr) in ("jmp","call","ret","retn"):
                    break

                if (idc.print_insn_mnem(now_addr) == 'push' ):
                    if  idc.print_operand(now_addr, 0) in ['offset']:             # 白名单，push的是一个变量
                        break
                    elif idc.get_operand_type(now_addr, 0) in [ idaapi.o_reg, idaapi.o_displ]:
                        # if 'ebp' in idc.print_operand(now_addr, 0):
                        #     break
                        print ("[!] Might be a format string vulnerablity : 0x%x %s [WARNING!]" % (now_addr,\
                                     idc.GetDisasm(now_addr)))
                        break
                if (idc.print_insn_mnem(now_addr) == 'mov' )and ('esp' in idc.print_operand(now_addr, 0)):
                    if idc.get_operand_type(now_addr, 1) in [ idaapi.o_reg, idaapi.o_displ ]:
                        print ("[!] Might be a format string vulnerablity : 0x%x %s [WARNING!]" % (now_addr,\
                                     idc.GetDisasm(now_addr)))
                    break

def check_arch():
    '''
        检查当前的x86的指令集架构，返回64 32 16
    '''
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
       bits = 16
    return bits
    

def fsb_check(bits):

    print ('[*]check for [printf].....')
    printf_plt = get_printf_plt()
    if printf_plt:
        print ('[*] printf@plt :' , hex(printf_plt))
        find_printf_fsb(printf_plt, bits)
    else:
        print ("[-] this is no printf@plt, pass....")

    print ('[*]check for [scanf]].....')
    scanf_plt = get_scanf_plt()
    if scanf_plt:
        print ('[*] isoc99_scanf@plt :' , hex(scanf_plt))
        find_scanf_fsb(scanf_plt, bits)
    else:
        print ("[-] this is no isoc99_scanf@plt, pass....")
    


if __name__ == '__main__':
    bits = check_arch()
    fsb_check(bits)  