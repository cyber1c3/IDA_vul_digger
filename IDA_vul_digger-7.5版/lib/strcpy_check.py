#encoding:utf-8
import idc
import idaapi
import idautils
import ida_frame
def twos_compl(val, bits):
   """compute the 2's complement of int value val"""
   # 如果设置了符号位，如8bit: 128-255 
   if (val & (1 << (bits - 1))) != 0: 
        #计算负值
       #print val
       val = val - (1 << bits)      
   #返回正值
   return val

#对ida7.0以上的兼容
def is_stack_buffer(addr, idx,bits):
    inst = idautils.DecodeInstruction(addr)

    try:# IDA < 7.0
        ret = get_stkvar(inst[idx], inst[idx].addr) != None
    except:# IDA >= 7.0
        #print type(inst[idx].addr)
        #print inst[idx].addr
        v = twos_compl(inst[idx].addr,bits)
        #print type(v)
        #print v
        ret = ida_frame.get_stkvar(inst, inst[idx], v)
    return ret

def find_arg32(addr, arg_num):
    function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)  # 获取函数所在段的起始地址
    steps = 0
    arg_count = 0
    # 预计检查指令在100条以内
    while steps < 100:    
        steps = steps + 1
        # 向前查看指令
        addr = idc.prev_head(addr)   
        # 获取前一条指令的名称
        op = idc.print_insn_mnem(addr).lower() 
        # 检查一下是否存在像ret,retn,jmp,b这样可以中断数据流的指令
        if op in ("call","ret", "retn", "jmp", "b") or addr < function_head:    
            return
        if op == "push":
            arg_count = arg_count + 1
            if arg_count == arg_num:
                  # 返回被push到堆栈的操作数
                return idc.print_operand(addr, 0)
        if (op == 'mov' )and ('esp' in idc.print_operand(addr, 0)) :
            arg_count+=1
            if arg_count == arg_num:
                # print idc.print_operand(addr, 0)
                return idc.print_operand(addr, 1)
                
def strcpy_check_32():    
    for functionAddr in idautils.Functions():# 检查所有函数
        if ".strcpy" in idc.get_func_name(functionAddr):
            xrefs = idautils.CodeRefsTo(functionAddr, False) # 遍历交叉引用，追踪函数执行过程
            for xref in xrefs:# 检查交叉引用是否是函数调用   

                if idc.print_insn_mnem(xref).lower() == "call":  
                    # 找到函数的第一个参数
                    opnd = find_arg32(xref, 1)
                    function_head = idc.get_func_attr(xref, idc.FUNCATTR_START)
                    addr = xref
                    _addr = xref
                    while True:
                        _addr = idc.prev_head(_addr)
                        _op = idc.print_insn_mnem(_addr).lower()
                        if _op in ("call","ret", "retn", "jmp", "b") or _addr < function_head:
                            break
                        elif _op == "lea" and idc.print_operand(_addr, 0) == opnd:
                            # 检查目标函数的缓冲区是否在堆栈当中
                            if is_stack_buffer(_addr, 1,32):
                                print ("[*] maybe a strcpy vul at 0x%X" % addr )
                                break
                       # 如果检测到要定位的寄存器是来自其他寄存器，则更新循环，在另一个寄存器中继续查找数据源
                        elif _op == "mov" and idc.print_operand(_addr, 0) == opnd:
                            op_type = idc.get_operand_type(_addr, 1)
                            if op_type == idaapi.o_reg:
                                opnd = idc.print_operand(_addr, 1)
                                addr = _addr
                            else:
                                break
def find_arg64(addr, arg_num):
    function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)  # 获取函数所在段的起始地址
    steps = 0
    arg_count = 0
    # 预计检查指令在100条以内
    while steps < 100:    
        steps = steps + 1
        # 向前查看指令
        addr = idc.prev_head(addr)   
        # 获取前一条指令的名称
        op = idc.print_insn_mnem(addr).lower()
        oparg1=idc.print_operand(addr,0)
        # 检查一下是否存在像ret,retn,jmp,b这样可以中断数据流的指令
        if op in ("ret", "retn", "jmp", "b") or addr < function_head:    
            return
        if op == "mov" and oparg1 in ['rdi','edi']:
            arg_count = arg_count + 1
            if arg_count == arg_num:
                # 返回被mov到rdi中的操作数
                # print idc.print_operand(addr, 1)
                return idc.print_operand(addr, 1)
                
def strcpy_check_64():
    for functionAddr in idautils.Functions():# 检查所有函数
        if ".strcpy" in idc.get_func_name(functionAddr):
            xrefs = idautils.CodeRefsTo(functionAddr, False) # 遍历交叉引用，追踪函数执行过程
            for xref in xrefs:# 检查交叉引用是否是函数调用   

                if idc.print_insn_mnem(xref).lower() == "call":  
                    # 找到函数的第一个参数
                    opnd = find_arg64(xref, 1)
                    function_head = idc.get_func_attr(xref, idc.FUNCATTR_START)
                    addr = xref
                    _addr = xref
                    while True:
                        _addr = idc.prev_head(_addr)
                        _op = idc.print_insn_mnem(_addr).lower()
                        if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                            break
                        elif _op == "lea" and idc.print_operand(_addr, 0) == opnd:
                            # 检查目标函数的缓冲区是否在堆栈当中
                            if is_stack_buffer(_addr, 1,64):
                                print ("[*] maybe a strcpy vul at 0x%X" % addr)
                                break
                       # 如果检测到要定位的寄存器是来自其他寄存器，则更新循环，在另一个寄存器中继续查找数据源
                        elif _op == "mov" and idc.print_operand(_addr, 0) == opnd:
                            op_type = idc.get_operand_type(_addr, 1)
                            if op_type == idaapi.o_reg:
                                opnd = idc.print_operand(_addr, 1)
                                addr = _addr
                            else:
                                break


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
    
    print ("[-] error! not 32 or 64 arch!")
    return 0
       
    
    
if __name__ == '__main__':
    bits = check_arch()
    print ('[*]program Arch :', bits)
    if bits==64:
        strcpy_check_64()
    if bits==32:
        strcpy_check_32()



