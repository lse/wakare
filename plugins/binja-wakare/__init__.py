import binaryninja

from binaryninja.enums import MessageBoxIcon, LowLevelILOperation, MessageBoxButtonSet
from binaryninja.lowlevelil import LowLevelILOperationAndSize
from binaryninja.interaction import MarkdownReport, ReportCollection, show_message_box, get_open_filename_input
from binaryninja.plugin import PluginCommand
from binaryninja import highlight

from binaryninjaui import UIActionHandler, UIAction, Menu, FileContext, ContextMenuManager, UIContext

from PySide2.QtWidgets import QApplication, QDialog, QTableWidget, QTableWidgetItem, QPushButton, QVBoxLayout
from PySide2.QtCore import Qt

from .dbutils import TraceDB, TraceDBError

# Global instance of the trace database
LOADED_DB = None

BRANCH_IL = [
        LowLevelILOperation.LLIL_CALL,
        LowLevelILOperation.LLIL_JUMP,
        LowLevelILOperation.LLIL_JUMP_TO,
        LowLevelILOperation.LLIL_GOTO,
        LowLevelILOperation.LLIL_IF # More of a hack for cond jump detection
]

# Dialogs
class XrefsDialog(QDialog):
    def __init__(self, bv, xref_list):
        super(XrefsDialog, self).__init__()

        # Init variables
        self.xref_list = xref_list
        self.bv = bv
        
        # Init widgets
        self.setWindowTitle("Branch xrefs")
        self.xref_table = QTableWidget(len(self.xref_list), 3)
        self.close_button = QPushButton("Close")

        self.xref_table.setHorizontalHeaderLabels(["Address", "Hitcount", "Function"])
        self.xref_table.verticalHeader().hide()
        self.xref_table.itemDoubleClicked.connect(self.table_cb)

        for i, e in enumerate(self.xref_list):
            address_item = QTableWidgetItem("0x{:x}".format(e[0]))
            hitcount_item = QTableWidgetItem("{}".format(e[1]))
            name_item = QTableWidgetItem(e[2])
            
            address_item.setFlags(Qt.ItemIsEnabled)
            hitcount_item.setFlags(Qt.ItemIsEditable)
            name_item.setFlags(Qt.ItemIsEditable)

            self.xref_table.setItem(i, 0, address_item)
            self.xref_table.setItem(i, 1, hitcount_item)
            self.xref_table.setItem(i, 2, name_item)

        self.xref_table.horizontalHeader().setStretchLastSection(True)

        # Init signals
        self.close_button.clicked.connect(self.close_cb)

        layout = QVBoxLayout()
        layout.addWidget(self.xref_table)
        layout.addWidget(self.close_button)

        self.setLayout(layout)

        self.setFixedWidth(self.xref_table.horizontalHeader().width())

    def close_cb(self):
        self.close()

    def table_cb(self, elem):
        addr = self.xref_list[elem.row()][0]
        self.bv.navigate(self.bv.view, addr)

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
    """ Decorator marking function needing a database instance """
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
def highlight_bbs(bv):
    """ Lists the hitcounts of all basic blocks in the program and colors the in the graph """
    global LOADED_DB
    max_val = -1

    highlight_color = highlight.HighlightColor(red=27, green=232, blue=0)

    for address, hitcount in LOADED_DB.get_hitcounts():
        bb = bv.get_basic_blocks_at(address)

        if max_val == -1:
            max_val = hitcount

        if len(bb) == 0:
            continue

        bb = bb[0]

        if bb.start == address:
            bb.set_user_highlight(highlight_color)
            bv.set_comment_at(address, "Hitcount: {}".format(hitcount))

@db_required
def clean_bbs_highlight(bv):
    """ Cleans the basic block highlighting and the comments """
    global LOADED_DB

    for address, hitcount in LOADED_DB.get_hitcounts():
        bb = bv.get_basic_blocks_at(address)

        if len(bb) == 0:
            continue

        bb = bb[0]

        if bb.start == address:
            bb.set_user_highlight(highlight.HighlightStandardColor.NoHighlightColor)
            bv.set_comment_at(address, "")

@db_required
def display_branch_xrefs(bv, addr):
    global LOADED_DB

    ins = get_llil_at(bv, addr)

    if not is_branch(ins):
        print_error("Code error", "This instruction is not a branch")
        return

    naked_xrefs = LOADED_DB.get_xrefs_from(addr) # xrefs with symbol names
    xrefs = []

    for target_addr, hitcount in naked_xrefs:
        fns = bv.get_functions_containing(target_addr)

        if fns:
            xrefs.append((target_addr, hitcount, fns[0].name))
        else:
            xrefs.append((target_addr, hitcount, "(unknown)"))

    dialog = XrefsDialog(bv, xrefs)
    dialog.exec_()


PluginCommand.register("Execution trace\\Load trace database", "Loads a trace database", db_load)
PluginCommand.register_for_address("Execution trace\\Branch xrefs from", "Displays xrefs from a branch", display_branch_xrefs)
PluginCommand.register("Execution trace\\Highlight basic blocks", "Highlights the hit basic blocks", highlight_bbs)
PluginCommand.register("Execution trace\\Clean basic block highlighting", "Cleans the highlighted basic blocks and comments", clean_bbs_highlight)
