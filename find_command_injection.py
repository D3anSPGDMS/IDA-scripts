import idaapi
import idautils
import idc

def get_function_address(function_name):
    """Retrieve the address of a function by its name."""
    func_addr = idc.get_name_ea_simple(function_name)
    if func_addr == idc.BADADDR:
        print(f"Function '{function_name}' not found.")
        return None
    return func_addr

def get_first_argument(call_ea):
    """Get the first argument of a function call."""
    # Assuming standard calling convention, the first argument is in `rdi` for x64 or `ecx`/`eax` for x86.
    # Adapt this logic for your specific architecture or calling convention.
    current_ea = call_ea
    while current_ea != idc.BADADDR:
        insn = idaapi.insn_t()
        idaapi.decode_prev_insn(insn, current_ea)
        if not insn:
            break
        current_ea = insn.ea
        
        if idc.print_insn_mnem(current_ea) in ["mov", "lea"]:  # Look for argument setup
            operand = idc.print_operand(current_ea, 0)
            if operand in ["edi", "rdi"]:  # Registers for the first argument
                value = idc.get_operand_value(current_ea, 1)
                str_value = idc.get_strlit_contents(value)
                #print(f"Found first argument at {hex(current_ea)}: {str_value}")
                return str_value
    return None

def find_calls_to_function(func_name):
    """Find all calls to a specific function and retrieve the first argument."""
    func_addr = get_function_address(func_name)
    if not func_addr:
        return

    print(f"Scanning for calls to '{func_name}' at address {hex(func_addr)}...")

    for ref in idautils.CodeRefsTo(func_addr, 0):
        print(f"Found call to {func_name} at {hex(ref)}")
        first_arg = get_first_argument(ref)
        if first_arg:
            if b"%s" in first_arg: 
                print(f"[May VULN]First argument for call at {hex(ref)}: {first_arg}")
            else:
                print(f"[NOT VULN]First argument for call at {hex(ref)}: {first_arg}")
        else:
            print(f"[May Vulnerable]No first argument found for call at {hex(ref)}")

if __name__ == "__main__":
    dangerous_funcs = [".execve", ".system", ".execvp", ".execl", ".popen"]
    for function_name in dangerous_funcs:
        find_calls_to_function(function_name)
