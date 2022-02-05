#encoding:utf-8

import idc
import idaapi
import idautils

danger_list=["gets","strcpy","scanf","strcat","system","popen","fork","fork","exe","pipe","alloc","free"]


def check_danger():
    for functionAddr in idautils.Functions():# 检查所有函数
        for d in danger_list:
            func_name=idc.get_func_name(functionAddr)
            if d in func_name :
                xrefs = idautils.CodeRefsTo(functionAddr, False) # 遍历交叉引用,追踪函数执行过程
                for xref in xrefs:
                    print ("[!] %s was called at :0x%x"%(func_name,xref))
                break


if __name__ == '__main__':
    print("[*] check for all dangeroust function:")
    check_danger()