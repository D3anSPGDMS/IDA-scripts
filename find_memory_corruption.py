from idautils import *
from idaapi import *
from idc import *


# Convert to signed value based on the word size (assuming 32-bit for this example)
word_size = 64  # Adjust to 64 for 64-bit binaries
max_unsigned = 2**word_size

def check_function_safety():
    unsafe_functions = [".strcpy", ".memcpy"]  # Functions to check
    func_usage = []

    for func_name in unsafe_functions:
        func_addr = get_name_ea_simple(func_name)
        if func_addr == BADADDR:
            print(f"{func_name} not found in the binary.")
            continue

        print(f"Analyzing calls to {func_name}...")
        for xref in CodeRefsTo(func_addr, 0):
            # Get function calling context
            caller_func = get_func(xref)
            if not caller_func:
                continue

            caller_name = get_func_name(caller_func.start_ea)
            # print(f"  Found call in function: {caller_name} in addr:{hex(xref)}")

            # Analyze arguments passed to the function
            # Assuming x86/x64 architecture, arguments may be passed via stack or registers
            args = get_call_arguments(xref)
            if args:
                # print(f"    Arguments: {args}")

                if func_name == ".strcpy":
                    src = args.get("src")  # src argument
                    dest = args.get("dest")  # dest argument
                    if src and dest:
                        check_strcpy_safety(dest, src, xref)

                elif func_name == ".memcpy":
                    src = args.get("src")
                    dest = args.get("dest")
                    size = args.get("size")
                    size_p = args.get("size_p")
                    if src and dest:
                        check_memcpy_safety(dest, src, size, size_p, xref)

def get_call_arguments(call_addr):
    """
    Get the arguments to strcpy at the given call address.
    Works for x86/x64 calling conventions.
    """
    args = {}

    # Analyze instructions before the call to extract arguments
    insn_addr = call_addr
    while insn_addr > 0:
        insn_addr = prev_head(insn_addr)
        mnemonic = print_insn_mnem(insn_addr)

        # Look for destination (first argument)
        if (mnemonic == "mov" or mnemonic == "lea") and print_operand(insn_addr, 0) == "rdi" and get_operand_type(insn_addr, 0) == o_reg:
            reg = print_operand(insn_addr, 0)
            mem = print_operand(insn_addr, 1)
            val = get_operand_value(insn_addr, 1)
            signed_val = val if val < (max_unsigned >> 1) else val - max_unsigned

            # Get the absolute value
            abs_val = abs(signed_val)
            args["dest"] = {"reg": reg, "mem": mem, "val": abs_val}

        # Look for source (second argument)
        if (mnemonic == "mov" or mnemonic == "lea") and print_operand(insn_addr, 0) == "rsi" and get_operand_type(insn_addr, 0) == o_reg:
            reg = print_operand(insn_addr, 0)
            mem = print_operand(insn_addr, 1)
            val = get_operand_value(insn_addr, 1)
            signed_val = val if val < (max_unsigned >> 1) else val - max_unsigned

            # Get the absolute value
            abs_val = abs(signed_val)
            args["src"] = {"reg": reg, "mem": mem, "val": abs_val}

            
        if mnemonic == "mov" and print_operand(insn_addr, 0) == "edx" and get_operand_type(insn_addr, 1) == o_imm:
            # print(f"[DEBUG] call_addr: {hex(call_addr)}, insn_addr: {hex(insn_addr)}")
            size = get_operand_value(insn_addr, 1)
            args["size"] = size
        elif mnemonic == "mov" and print_operand(insn_addr, 0) == "rdx":
            # the size argument is not immediate number
            args["size_p"] = print_operand(insn_addr, 1)
        # Stop if we’ve analyzed enough instructions
        if len(args) >= 3:
            break

    return args

def check_strcpy_safety(dest, src, call_addr):
    """
    Check if strcpy is safe by analyzing dest and src.
    """
    # print(f"    Checking strcpy at {hex(call_addr)}...")
    # Example: Add size-checking logic here for `src` and `dest`
    # Trace back to see if dest buffer size is validated
    if "[rbp-" in dest["mem"]: # or "[rsp+" in dest["mem"]:
        print(f"[**VULNERABLE**] (strcpy)Buffer overflow here {hex(call_addr)}")
        print(dest, src)

def check_memcpy_safety(dest, src, size, size_p, call_addr):
    """
    Check if memcpy is safe by analyzing dest, src, and size.
    """
    # print(f"    Checking memcpy at {hex(call_addr)}...")
    if size is not None:
        print(f"[INFO] The size:{size} is an immediate number! ({hex(call_addr)})")
        # Example: Validate size against the destination buffer
        # Trace size back to its origin to ensure it’s within valid bounds
        if size > dest["val"] and dest["val"] != 0 and ("rbp" in dest["mem"] or "rsp" in dest["mem"]):
            print(f"[*****VULNERABLE*****] (memcpy)Buffer overflow here {hex(call_addr)}")
            print(dest, "Size:", size)
    elif size_p:
        print(f"[INFO] The size:{size_p} is indirect value... of {hex(call_addr)}")
        
    return

# Run the safety check
check_function_safety()
