def get_vm_log_breakpoint_template(addresses, handler_ids = None, pie=True, print_handlers=False):
    if handler_ids is None:
        handler_ids = []
    else:
        assert len(handler_ids) == len(addresses)

    def get_func_name(i):
        func_id = handler_ids[i] if len(handler_ids) != 0 else i
        return f"vm_handler_{func_id}"

    for i, addr in enumerate(addresses):
        func_id = handler_ids[i] if len(handler_ids) != 0 else i
        func_name_template = f'def {get_func_name(i)}\n    return "OP{func_id}"\n'
        print(func_name_template)

    print()

    for i, addr in enumerate(addresses):
        if pie:
            bp_template = "LogBreakpoint.create_pie_bp"
        else:
            bp_template = "LogBreakpoint.create_pt_bp"

        print(f"{bp_template}({hex(addr)}, {get_func_name(i)})")
