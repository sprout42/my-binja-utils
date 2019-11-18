import binaryninja as bn

from string_utils import *

bn.PluginCommand.register_for_range("String Creator", "Finds and defines all strings across range", define_strings_vars_range)
