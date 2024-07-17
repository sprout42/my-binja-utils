import os
import os.path

import binaryninja as bn
from binaryninja.enums import SymbolType
from binaryninja.types import Type, NamedTypeReferenceType, FunctionType, \
        PointerType, PointerBuilder, Symbol


# TODO:
# mosquitto
# openssl
# pcap


def update_func_refs(bv, var):
    if var.symbol.type == SymbolType.FunctionSymbol:
        var_addr = var.start
    elif var.symbol.type in (SymbolType.ExternalSymbol, SymbolType.ImportedDataSymbol):
        var_addr = var.address
    elif var.symbol.type == SymbolType.SymbolicFunctionSymbol:
        # Do nothing
        return
    else:
        raise Exception('Invalid object type: %s(%s, %s)' % (var, var.type, var.symbol))

    # Both functions and imported function references show up as Function Types
    if not isinstance(var.type, FunctionType):
        print('Cannot update references for %s @ 0x%x (%s)' % (var.name, var_addr, var.type))
        return

    for ref_addr in bv.get_data_refs(var_addr):
        ref = bv.get_data_var_at(ref_addr)
        if ref.name != var.name or ref.type != var.type:
            print('fixing %s @ 0x%x ref: 0x%x' % (var.name, var_addr, ref.address))
            ref.name = var.name
            ref.type = PointerBuilder.create(var.type)
            ref.symbol = Symbol(SymbolType.ImportedDataSymbol, ref.address, var.name)


def fix_function_references_in_section(bv, sections=None):
    # The common sections we need to fix things in are .extern and .got
    if sections is None:
        sections = ['.extern', '.got']
    elif isinstance(sections, str):
        sections = [sections]

    state = bv.begin_undo_actions()
    for name in sections:
        section = bv.get_section_by_name(name)
        fix_function_references(bv, section.start, section.length)

    # Now go through each function in the PLT, if it has an entry in the .got or 
    # .extern section make sure it has the proper type
    plt = bv.get_section_by_name('.plt')
    if plt is not None:
        print('Verifying function prototypes in .plt: 0x%x - 0x%x' % (plt.start, plt.end))
        addr = bv.get_next_function_start_after(plt.start-1)
        while addr is not None and addr < plt.end:
            func = bv.get_function_at(addr)

            # get the next address
            addr = bv.get_next_function_start_after(func.start)

            # see if this function exists in .text or .got and get the function 
            # prototype from that function.
            syms = dict((bv.get_sections_at(s.address)[0].name, s) for s in bv.get_symbols_by_name(func.name))
            if '.text' in syms:
                text_func = bv.get_function_at(syms['.text'].address)
                typ = text_func.type

            elif '.got' in syms:
                var = bv.get_data_var_at(syms['.got'].address)
                # Remove un-function pointer this type
                parts = str(var.type).partition('(*)')
                try:
                    typ, typname = bv.parse_type_string(parts[0] + parts[2])
                except SyntaxError as exc:
                    print('Error trying to parse type for %s @ 0x%x: %s' % (func.name, func.start, parts[0] + parts[2]))
                    raise

            else:
                # No prototype found for function, skip it
                continue

            if typ is not None and str(func.type) != str(typ):
                print('Updating function %s @ 0x%x prototype "%s" to "%s"' % (func.name, func.start, func.type, typ))
                func.type = typ

    bv.commit_undo_actions(state)


def fix_function_references_over_range(bv, start, length):
    state = bv.begin_undo_actions()
    fix_function_references(bv, start, length)
    bv.commit_undo_actions(state)


def fix_function_references(bv, start, length):
    # Parse our types, read these from a file, so we don't have to reload binja 
    # every time the types/functions get updated
    sources = []
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    for entry in os.scandir(os.path.join(plugin_dir, 'sources')):
        if not entry.name.startswith('.') and entry.is_file():
            print('Reading sources from %s' % entry.name)
            with open(os.path.join(plugin_dir, 'sources', entry.name)) as f:
                sources.append(f.read())
    parsed_types = bv.parse_types_from_string('\n'.join(sources))

    for typname, typ in parsed_types.types.items():
        # If this type isn't defined yet, define it
        existing_typ = bv.get_type_by_name(typname)
        if existing_typ is None:
            print('defining type %s as [%d]: %r' % (typname, (typ.width+7) // 8, typ.children))
            bv.define_type(Type.generate_auto_type_id("source", typname), typname, typ)
        #else:
        #    print('%s already defined as [%d]: %r, not defining [%d] %r' % (
        #        typname,
        #        (existing_typ.width+7) // 8, existing_typ.children,
        #        (typ.width+7) // 8, typ.children))

    # Info about where we are fixing references
    section = bv.get_sections_at(start)[0]
    if section:
        section_name = section.name
    else:
        section_name = '<unknown>'

    end = start + length
    print('Fixing function references in section %s: 0x%x - 0x%x' % (section_name, start, end))

    # Fix references
    var = bv.get_data_var_at(start)
    while var is not None and var.address < end:
        points_to_func = False
        if not isinstance(var.type, NamedTypeReferenceType) and isinstance(var.value, int):
            func = bv.get_function_at(var.value)
            if func is None:
                func = bv.get_data_var_at(var.value)
                if func is not None and isinstance(func.type, FunctionType):
                    func_addr = func.address
                    points_to_func = True
            else:
                func_addr = func.start
                points_to_func = True
        else:
            func = None

        if isinstance(var.type, FunctionType):
            typ = parsed_types.functions.get(var.name)
            if typ is not None and str(var.type) != str(typ):
                print('updating signature for %s @ 0x%x: %s' % (var.name, var.address, typ))
                var.type = typ
            update_func_refs(bv, var)

        elif isinstance(var.type, PointerType) and points_to_func:
            typ = parsed_types.functions.get(func.name)
            if typ is not None and str(var.type) != str(typ):
                print('updating signature for %s @ 0x%x: %s' % (func.name, func_addr, typ))
                func.type = typ
            update_func_refs(bv, func)

        elif var.symbol is None or var.symbol.type != SymbolType.ImportedDataSymbol:
            # If this object is in the functions list fix it now
            typ = parsed_types.functions.get(var.name)
            if typ is not None and str(var.type) != str(typ):
                print('updating signature for %s @ 0x%x: %s' % (var.name, var.address, typ))
                var.type = typ

                # All normal functions should have been caught in the previous 
                # branch, this is only to catch imported functions that have not 
                # properly been identified as imported functions. so we only 
                # update function references if the data variable name is in the 
                # extra/custom functions we've parsed in this plugin.
                update_func_refs(bv, var)

        else:
            print('%s @ 0x%x (%s) not a function' % (var.name, var.address, var.type))
            if func is not None:
                if func.symbol.type == SymbolType.FunctionSymbol:
                    print('%s @ 0x%x (%s)' % (func.name, func.start, func.symbol.type))
                elif func.symbol.type == SymbolType.ExternalSymbol:
                    print('%s @ 0x%x (%s)' % (func.name, func.address, func.symbol.type))

        var = bv.get_next_data_var_after(var.address)


bn.PluginCommand.register("Fix Function References", "", fix_function_references_in_section)
bn.PluginCommand.register_for_range("Fix Function References Over Range", "", fix_function_references_over_range)
