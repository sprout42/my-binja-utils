import os
import os.path

import binaryninja as bn
from binaryninja.enums import SymbolType
from binaryninja.types import Type, NamedTypeReferenceType, FunctionType, PointerType, PointerBuilder, Symbol


# TODO:
# pthread
# mosquitto
# openssl
# pcap


def update_func_refs(bv, var):
    if var.symbol.type == SymbolType.FunctionSymbol:
        var_addr = var.start
    elif var.symbol.type == SymbolType.ExternalSymbol:
        var_addr = var.address
    elif var.symbol.type in (SymbolType.SymbolicFunctionSymbol,
                             SymbolType.ImportedDataSymbol):
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


def fix_function_references_in_section(bv, section_name=None):
    if section_name is None:
        section_name = '.extern'
    section = bv.get_section_by_name(section_name)
    fix_function_references(bv, section.start, section.length)


def fix_function_references(bv, start, length):
    end = start + length

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
    print('Fixing function references in section %s: 0x%x - 0x%x' % (section_name, start, end))

    state = bv.begin_undo_actions()

    # Fix references
    var = bv.get_data_var_at(start)
    while var is not None:
        if not isinstance(var.type, NamedTypeReferenceType) and \
                isinstance(var.value, int):
            func = bv.get_function_at(var.value)
        else:
            func = None

        if isinstance(var.type, FunctionType):
            typ = parsed_types.functions.get(var.name)
            if typ and var.type != typ:
                print('updating signature for %s @ 0x%x: %s' % (var.name, var.address, typ))
                var.type = typ
            update_func_refs(bv, var)

        elif isinstance(var.type, PointerType) and func:
            typ = parsed_types.functions.get(func.name)
            if typ and var.type != typ:
                print('updating signature for %s @ 0x%x: %s' % (func.name, func.start, typ))
                func.type = typ
            update_func_refs(bv, func)

        elif var.symbol is None or var.symbol.type != SymbolType.ImportedDataSymbol:
            typ = parsed_types.functions.get(var.name)
            if typ is not None and var.type != typ:
                print('updating signature for %s @ 0x%x: %s' % (var.name, var.address, typ))
                var.type = typ
            update_func_refs(bv, var)

        else:
            print('%s @ 0x%x not a function' % (var.name, var.address))

        var = bv.get_next_data_var_after(var.address)

    bv.commit_undo_actions(state)


bn.PluginCommand.register("Fix Function References", "", fix_function_references_in_section)
bn.PluginCommand.register_for_range("Fix Function References Over Range", "", fix_function_references)
