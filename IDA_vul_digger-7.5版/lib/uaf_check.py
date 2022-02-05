#encoding:utf-8
import idc
import idaapi
import idautils

malloc_func_list = []
free_func =0



def uaf_check64():
    for functionAddr in idautils.Functions():# 检查所有函数
            if "free" in idc.get_func_name(functionAddr):
                xrefs = CodeRefsTo(functionAddr, False) # 遍历交叉引用，追踪函数执行过程
                for xref in xrefs:# 检查交叉引用是否是函数调用
                    print(xref)



if __name__ == '__main__':
    bits = check_arch()
    print ('[*] program Arch %d:'%bits,"\n")
    print ('[+] start check UAF...')
    if bits==64:
        uaf_check64()
    if bits==32:
        uaf_check64()
    print ('[+] finish check UAF \n')

