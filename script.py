import angr, claripy, monkeyhex



proj = angr.Project('./bit_check',main_opts={'base_addr': 0})

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(30)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

print(proj.loader)

state = proj.factory.entry_state(stdin=flag)

sm = proj.factory.simulation_manager(state)

sm.explore(find=0x258B, avoid=0x25A3)
