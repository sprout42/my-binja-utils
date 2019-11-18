import binaryninja as bn

def define_strings_vars_range(bv, addr_start, addr_len):
    br = bn.BinaryReader(bv)
    #print('Starting string search at {:x}'.format(addr_start))
    bv.begin_undo_actions()
    for possible_str in bv.get_strings(addr_start, addr_len):
        br.seek(possible_str.start + possible_str.length)
        end_char = chr(br.read8())
        #print('char @ {:x} == {}'.format(possible_str.start + possible_str.length, end_char))
        if end_char == '\x00':
            #print('found string @ {0.start:x} len {0.length:x}'.format(possible_str))
            str_type, _ = bv.parse_type_string('char [{}]'.format(possible_str.length))
            bv.define_user_data_var(possible_str.start, str_type)
    bv.commit_undo_actions()
    #print('done')

bn.PluginCommand.register_for_range("String Creator", "Finds and defines all strings across range", define_strings_vars_range)
