import functools
import binaryninja

from binaryninja.enums import MessageBoxIcon, LowLevelILOperation, MessageBoxButtonSet
from binaryninja.lowlevelil import LowLevelILOperationAndSize
from binaryninja.interaction import MarkdownReport, ReportCollection, show_message_box, get_open_filename_input
from binaryninja.plugin import PluginCommand
from binaryninja import highlight

from PySide2.QtWidgets import QApplication
from PySide2.QtCore import Qt

from binaryninjaui import UIActionHandler, UIAction, Menu, FileContext, ContextMenuManager, UIContext, DockHandler

from .dbutils import TraceDB, TraceDBError
from .view import XrefsDialog, BBViewerWidget

# Global instance of the trace database
LOADED_DB = None

BRANCH_IL = [
        LowLevelILOperation.LLIL_CALL,
        LowLevelILOperation.LLIL_JUMP,
        LowLevelILOperation.LLIL_JUMP_TO,
        LowLevelILOperation.LLIL_GOTO,
        LowLevelILOperation.LLIL_IF # More of a hack for cond jump detection
]

def print_error(title, message):
    show_message_box(title, message, icon=MessageBoxIcon.ErrorIcon)

def is_branch(ins):
    for subins in ins.prefix_operands:
        if isinstance(subins, LowLevelILOperationAndSize) and subins.operation in BRANCH_IL:
            return True

    return False

def get_llil_at(bv, addr):
    """ Gets the low level il instruction at given vaddr """
    fns = bv.get_functions_containing(addr)

    if len(fns) == 0:
        return None

    ins = None

    for fn in fns:
        ins = fn.get_low_level_il_at(addr)

        if ins:
            return ins

    return None

def db_required(func):
    """ Decorator marking functions needing a database instance """
    global LOADED_DB

    def inner(*args, **kwargs):
        if not LOADED_DB:
            print_error("Database Error", 
                    "No trace was loaded.Please open a trace databse.")
        else:
            func(*args, **kwargs)

    return inner

def db_load(bv):
    global LOADED_DB

    if LOADED_DB:
        res = show_message_box("Database loading", 
                "A trace is already loaded. Do you want to overwrite it ?",
                buttons=MessageBoxButtonSet.YesNoButtonSet,
                icon=MessageBoxIcon.WarningIcon)

        if not res:
            return

        LOADED_DB = None

    path = get_open_filename_input("Select trace database")
    
    if not path:
        return
    
    path = path.decode("UTF-8")

    try:
        LOADED_DB = TraceDB(bv, path)

        text = ""
        text += "Mappings: {:n}\n".format(LOADED_DB.mapping_count)
        text += "Branches: {:n}\n".format(LOADED_DB.branch_count)
        text += "bb hits : {:n}\n".format(LOADED_DB.hitcount_count)

        show_message_box("Trace info", text)

    except sqlite3.Error as e:
        print_error("Database error", "sqlite error: {}".format(e))
        LOADED_DB = None
    except TraceDBError as e:
        print_error("Database error", "Trace init error: {}".format(e))
        LOADED_DB = None

@db_required
def display_branch_xrefs(bv, addr):
    global LOADED_DB

    ins = get_llil_at(bv, addr)

    if not is_branch(ins):
        print_error("Code error", "This instruction is not a branch")
        return

    dialog = XrefsDialog(addr, bv, LOADED_DB)
    dialog.exec_()

@db_required
def display_bb_viewer(bv):
    dock_handler = None

    for wg in QApplication.allWidgets():
        wg_win = wg.window()
        dock_handler = wg_win.findChild(DockHandler, "__DockHandler")

        if dock_handler:
            break

    if dock_handler is None:
        print("Could not find DockHandler")
        return

    dock_widget = BBViewerWidget("Basic Block viewer", dock_handler.parent(), bv, LOADED_DB)
    dock_handler.addDockWidget(dock_widget, Qt.RightDockWidgetArea, Qt.Vertical, True)

PluginCommand.register("Execution trace\\Load trace database", "Loads a trace database", db_load)
PluginCommand.register_for_address("Execution trace\\Branch xrefs from", "Displays xrefs from a branch", display_branch_xrefs)

PluginCommand.register("Execution trace\\Show basic block viewer", "Displays information about basic blocks", display_bb_viewer)
