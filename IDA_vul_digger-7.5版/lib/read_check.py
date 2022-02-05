#encoding:utf-8
import idc
import idaapi
import idautils



def twos_compl(val, bits):
    """compute the 2's complement of int value val"""
    # 如果设置了符号位，如8bit: 128-255 
    if (val & (1 << (bits - 1))) != 0: 
        #计算负值
        #print val
        val = val - (1 << bits)
        #返回正值
    return val


def find_arg32(addr, arg_num):
    function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)  # 获取函数所在段的起始地址
    steps = 0
    arg_count=0
    # 预计检查指令在100条以内
    while steps < 100:    
        steps = steps + 1
        # 向前查看指令
        addr = idc.prev_head(addr)   
        # 获取前一条指令的名称
        op = idc.print_insn_mnem(addr).lower()
        oparg1=idc.print_operand(addr,0)
        
        # 检查一下是否存在像ret,retn,jmp,b这样可以中断数据流的指令
        if op in ("call","ret", "retn", "jmp", "b") or addr < function_head:    
            return
        if op == "push" :
            arg_count+=1
            if arg_count == arg_num:
                # print idc.print_operand(addr, 0)
                return idc.print_operand(addr, 0)
        if (op == 'mov' )and ('esp' in idc.print_operand(addr, 0)) :
            arg_count+=1
            if arg_count == arg_num:
                # print idc.print_operand(addr, 1)
                return idc.print_operand(addr, 1)


def read_check_32():
    for functionAddr in idautils.Functions():# 检查所有函数
        if "read" in idc.get_func_name(functionAddr):
            xrefs = idautils.CodeRefsTo(functionAddr, False) # 遍历交叉引用，追踪函数执行过程
            for xref in xrefs:# 检查交叉引用是否是函数调用   
                # print ("\n\n",hex(xref)
                if idc.print_insn_mnem(xref).lower() == "call":  
                    # 找到函数的第一个参数
                    function_head = idc.get_func_attr(xref, idc.FUNCATTR_START)
                    # print hex(xref)
                    opnd = find_arg32(xref, 2)
                    # print find_arg32(xref, 3)
                    # print type(opnd),opnd
                    # print idc.print_insn_mnem(xref)
                    # size= int("0x"+find_arg32(xref, 3).replace("h",""),16)
                    try:
                        size= int("0x"+find_arg32(xref, 3).replace("h",""),16)
                    except :
                        print ("[-] something error, addr:0x%x"%xref)
                        continue
                    # print type(size),hex(size)

                    if "offset" in opnd:
                        pre_addr=xref
                        while True:
                            pre_addr=idc.prev_head(pre_addr)
                            pre_op=idc.print_operand(pre_addr,0)
                            # print hex(pre_addr),pre_op
                            if "offset" in pre_op:
                                var_addr=idc.get_operand_value(pre_addr,0)
                                var_size =idc.get_item_size(var_addr)
                                if size>var_size:
                                    print ("[*] find a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                                    
                                else:
                                    print ("[*] maybe a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                                    # print hex(var_addr)
                                break



                    addr =xref
                    _addr = xref
                    while True:
                        _addr = idc.prev_head(_addr)#获取call指令的上一条指令地址
                        _op = idc.print_insn_mnem(_addr).lower()
                        # print ("_op:",_op
                        if _op in ("call","ret", "retn", "jmp", "b") or _addr < function_head:
                            break
                        elif _op == "lea" and idc.print_operand(_addr, 0) == opnd:
                            inst = idautils.DecodeInstruction(_addr)
                            buf_size =(~(twos_compl(inst[1].addr,32))+1)
                            
                            if buf_size<size:
                                print ("[*] maybe a stack overflow at 0x%x"%(addr))
                                print ("read size:",hex(size),"buf size:",hex(buf_size))
                            # print hex(inst[1].addr)
                            # print hex(buf_size)
                            break

                        elif _op in ("mov","lea") and idc.print_operand(_addr, 0) == opnd and "offset" in idc.print_operand(_addr, 1):
                            var_addr=idc.get_operand_value(pre_addr,1)
                            var_size =idc.get_item_size(var_addr)
                            if size>var_size:
                                print ("[*] find a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                            else:
                                print ("[*] maybe a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                            # print hex(var_addr)
                            break

                       # 如果检测到要定位的寄存器是来自其他寄存器，则更新循环，在另一个寄存器中继续查找数据源
                        elif _op == "mov" and idc.print_operand(_addr, 0) == opnd:
                            op_type = idc.get_operand_type(_addr, 1)
                            print ("type:",op_type)
                            if op_type == idaapi.o_reg:
                                opnd = idc.print_operand(_addr, 1)
                                addr = _addr
                            else:
                                break

def find_arg64(addr, arg_num):
    function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)  # 获取函数所在段的起始地址
    steps = 0

    # 预计检查指令在100条以内
    while steps < 100:    
        steps = steps + 1
        # 向前查看指令
        addr = idc.prev_head(addr)   
        # 获取前一条指令的名称
        op = idc.print_insn_mnem(addr).lower()
        oparg1=idc.print_operand(addr,0)
        # 检查一下是否存在像ret,retn,jmp,b这样可以中断数据流的指令
        if op in ("call","ret", "retn", "jmp", "b") or addr < function_head:    
            return
        if op == "mov" and oparg1 in ['rdi','edi']:
            arg_count=1
            if arg_count == arg_num:
                # 返回被mov到rdi中的操作数
                # print idc.print_operand(addr, 1)
                return idc.print_operand(addr, 1)
        if op == "mov"and oparg1 in ['rsi','esi']:
            arg_count=2
            if arg_count == arg_num:
                # 返回被mov到rdi中的操作数
                # print idc.print_operand(addr, 1)
                return idc.print_operand(addr, 1)
        if op == "mov" and oparg1 in ['rdx','edx']:
            arg_count=3
            if arg_count == arg_num:
                # 返回被mov到rdi中的操作数
                # print idc.print_operand(addr, 1)
                return idc.print_operand(addr, 1)

def read_check_64():
    for functionAddr in idautils.Functions():# 检查所有函数
        if "read" in idc.get_func_name(functionAddr):
            xrefs = idautils.CodeRefsTo(functionAddr, False) # 遍历交叉引用，追踪函数执行过程
            for xref in xrefs:# 检查交叉引用是否是函数调用   
                # print ("\n\n",hex(xref)
                if idc.print_insn_mnem(xref).lower() == "call":  
                    # 找到函数的第一个参数
                    function_head = idc.get_func_attr(xref, idc.FUNCATTR_START)
                    opnd = find_arg64(xref, 2)
                    # print type(opnd),opnd
                    # print hex(xref)
                    # print idc.print_insn_mnem(xref)
                    try:
                        size= int("0x"+find_arg64(xref, 3).replace("h",""),16)
                    except :
                        print ("[-] something error, addr:0x%x"%xref)
                        continue
                    
                    # print type(opnd),opnd
                    # print type(size),hex(size)

                    if "offset" in opnd:
                        pre_addr=xref
                        while True:
                            pre_addr=idc.prev_head(pre_addr)
                            pre_op=idc.print_operand(pre_addr,1)
                            # print hex(pre_addr),pre_op
                            if "offset" in pre_op:
                                var_addr=idc.get_operand_value(pre_addr,1)
                                var_size =idc.get_item_size(var_addr)
                                if size>var_size:
                                    print ("[*] find a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                                    
                                else:
                                    print ("[*] maybe a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                                    # print hex(var_addr)
                                break



                    addr =xref
                    _addr = xref
                    while True:
                        _addr = idc.prev_head(_addr)#获取call指令的上一条指令地址
                        _op = idc.print_insn_mnem(_addr).lower()
                        # print ("_op:",_op
                        if _op in ("call","ret", "retn", "jmp", "b") or _addr < function_head:
                            break
                        elif _op == "lea" and idc.print_operand(_addr, 0) == opnd:
                            inst = idautils.DecodeInstruction(_addr)
                            buf_size =(~(twos_compl(inst[1].addr,64))+1)
                            
                            if buf_size<size:
                                print ("[*] maybe a stack overflow at 0x%x"%(addr))
                                print ("read size:",hex(size),"buf size:",hex(buf_size))
                            # print hex(inst[1].addr)
                            # print hex(buf_size)
                            break

                        elif _op in ("mov","lea") and idc.print_operand(_addr, 0) == opnd and "offset" in idc.print_operand(_addr, 1):
                            var_addr=idc.get_operand_value(pre_addr,1)
                            var_size =idc.get_item_size(var_addr)
                            if size>var_size:
                                print ("[*] find a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                            else:
                                print ("[*] maybe a bss overflow call at:0x%x,buf: 0x%x[size:0x%x],input size:0x%x"%(xref,var_addr,var_size,size))
                                # print hex(var_addr)
                            break
                       # 如果检测到要定位的寄存器是来自其他寄存器，则更新循环，在另一个寄存器中继续查找数据源
                        elif _op == "mov" and idc.print_operand(_addr, 0) == opnd:
                            op_type = idc.get_operand_type(_addr, 1)
                            print ("type:",op_type)
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
    print ('[*] program Arch %d:'%bits,"\n")
    print ('[+] start check read func...')
    if bits==64:
        read_check_64()
    if bits==32:
        read_check_32()
    print ('[+] finish check read func\n')
    