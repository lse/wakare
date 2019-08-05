import math
import sqlite3

from PySide2.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QCheckBox, QGroupBox
from PySide2.QtCore import Qt

from binaryninjaui import DockContextHandler, UIActionHandler
from binaryninja.highlight import HighlightColor, HighlightStandardColor
from binaryninja.enums import MessageBoxIcon
from binaryninja.interaction import show_message_box, get_open_filename_input

from .dbutils import TraceDB, TraceDBError


def _name_from_address(bv, address):
    bbs = bv.get_basic_blocks_at(address)

    if not bbs:
        return "(unknown)"

    bb = bbs[0]
    symbol = bv.get_symbol_at(bb.start)

    # If we are in a function we take the name. Otherwise we have a lone basic block (Some C++ virtual function)
    if bb.function:
        symbol = bv.get_symbol_at(bb.function.start)

        if not symbol:
            return bb.function.name
    else:
        print("(not symbol) BB at 0x{:x} -> {}".format(bb.start, symbol))
        return "(unknown)"

    if symbol.full_name:
        return symbol.full_name

    return symbol.name


def _print_error(title, msg):
    show_message_box(title, msg, icon=MessageBoxIcon.ErrorIcon)


def _load_db(bv):
    path = get_open_filename_input("Select trace database")

    if not path:
        return None

    path = path.decode("UTF-8")

    try:
        db = TraceDB(bv, path)
        return db
    except TraceDBError as e:
        _print_error("Database error", "Loading error: {}".format(e))
    except sqlite3.Error as e:
        _print_error("Database error", "sqlite error: {}".format(e))


class XrefsDialog(QDialog):
    def __init__(self, branch_address, bv, db):
        super(XrefsDialog, self).__init__()

        # Init variables
        self.bv = bv
        self.branch_address = branch_address
        self.xref_list = db.get_xrefs_from(branch_address)

        # Init widgets
        self.setWindowTitle("Xrefs for branch at 0x{:x}".format(branch_address))
        self.xref_table = QTableWidget(len(self.xref_list), 3)
        self.close_button = QPushButton("Close")

        self.xref_table.setHorizontalHeaderLabels(["Address", "Hitcount", "Function"])
        self.xref_table.verticalHeader().hide()
        self.xref_table.itemDoubleClicked.connect(self._table_cb)

        for i, e in enumerate(self.xref_list):
            address_item = QTableWidgetItem("0x{:x}".format(e[0]))
            hitcount_item = QTableWidgetItem("{}".format(e[1]))
            name_item = QTableWidgetItem(_name_from_address(bv, e[0]))

            address_item.setFlags(Qt.ItemIsEnabled)
            hitcount_item.setFlags(Qt.ItemIsEditable)
            name_item.setFlags(Qt.ItemIsEditable)

            self.xref_table.setItem(i, 0, address_item)
            self.xref_table.setItem(i, 1, hitcount_item)
            self.xref_table.setItem(i, 2, name_item)

        self.xref_table.horizontalHeader().setStretchLastSection(True)

        # Init signals
        self.close_button.clicked.connect(self._close_cb)

        layout = QVBoxLayout()
        layout.addWidget(self.xref_table)
        layout.addWidget(self.close_button)

        self.setLayout(layout)

        self.setFixedWidth(self.xref_table.horizontalHeader().width())

    def _close_cb(self):
        self.close()

    def _table_cb(self, elem):
        addr = self.xref_list[elem.row()][0]
        self.bv.navigate(self.bv.view, addr)


class BBViewerWidget(QWidget, DockContextHandler):
    PER_PAGE_COUNT = 50

    def __init__(self, name, parent, bv, db):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.hitcounts = []
        self.orig_hitcounts = []
        self.db = db
        self.bv = bv
        self.descending = True
        self.highlight = False
        self.current_page = 0

        self.hitcounts = self.db.get_hitcounts()
        self.orig_hitcounts = [e for e in self.hitcounts]

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        vlayout = QVBoxLayout()

        # Top label
        self.hitcount_counter = QLabel("Basic block count: {}".format(self.db.hitcount_count))
        self.hitcount_counter.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        # BB Hitcount table
        self.hit_table = QTableWidget(0, 3)
        self.hit_table.setHorizontalHeaderLabels(["Address", "Hitcount", "Function"])
        self.hit_table.verticalHeader().hide()
        self.hit_table.horizontalHeader().setStretchLastSection(True)
        self.hit_table.itemDoubleClicked.connect(self._cb_table)
        self._render_page()

        # Option buttons
        optionslayout = QHBoxLayout()
        optionsbox = QGroupBox("Options")

        ascending_checkbox = QCheckBox("Sort ascending")
        highlight_checkbox = QCheckBox("Highlight basic blocks")

        ascending_checkbox.stateChanged.connect(self._cb_ascending)
        highlight_checkbox.stateChanged.connect(self._cb_highlight)

        optionslayout.addWidget(ascending_checkbox)
        optionslayout.addWidget(highlight_checkbox)
        optionsbox.setLayout(optionslayout)

        # Diffing buttons
        diffinglayout = QHBoxLayout()
        diffingoptions = QGroupBox("Diffing")

        diffing_reset_button = QPushButton("Reset")
        diffing_diff_button = QPushButton("Difference")
        diffing_inter_button = QPushButton("Intersection")

        diffing_reset_button.clicked.connect(self._cb_diff_reset)
        diffing_diff_button.clicked.connect(self._cb_diff_diff)
        diffing_inter_button.clicked.connect(self._cb_diff_inter)

        diffinglayout.addWidget(diffing_diff_button)
        diffinglayout.addWidget(diffing_inter_button)
        diffinglayout.addWidget(diffing_reset_button)

        diffingoptions.setLayout(diffinglayout)

        # Bottom buttons for page change
        prevnextlayout = QHBoxLayout()
        self.back_button = QPushButton("<")
        self.next_button = QPushButton(">")
        self.page_count_label = QLabel("")
        self.page_count_label.setAlignment(Qt.AlignCenter)
        self._render_nav_line()

        self.back_button.clicked.connect(self._cb_prev_page)
        self.next_button.clicked.connect(self._cb_next_page)

        prevnextlayout.addWidget(self.back_button)
        prevnextlayout.addWidget(self.page_count_label)
        prevnextlayout.addWidget(self.next_button)

        vlayout.addWidget(self.hitcount_counter)
        vlayout.addWidget(self.hit_table)
        vlayout.addWidget(optionsbox)
        vlayout.addWidget(diffingoptions)
        vlayout.addLayout(prevnextlayout)

        self.setLayout(vlayout)

    def _cb_table(self, elem):
        addr = self.hitcounts[(BBViewerWidget.PER_PAGE_COUNT * self.current_page) + elem.row()][0]
        self.bv.navigate(self.bv.view, addr)

    def _cb_ascending(self, elem):
        self.descending = not self.descending
        self.hitcounts = sorted(self.hitcounts, key=lambda a: a[1], reverse=self.descending)
        self.current_page = 0

        self._render_nav_line()
        self._render_page()

    def _cb_prev_page(self, elem):
        # We do not need to check as _render_nav_line disables the button at the limit
        self._render_nav_line()
        self.current_page -= 1
        self._render_nav_line()
        self._render_page()

    def _cb_next_page(self, elem):
        # We do not need to check as _render_nav_line disables the button at the limit
        self._render_nav_line()
        self.current_page += 1
        self._render_nav_line()
        self._render_page()

    def _cb_highlight(self, elem):
        self.highlight = not self.highlight
        self._bb_highlight(self.highlight)

    def _cb_diff_reset(self, item):
        if self.highlight:
            self._bb_highlight(False)

        self.hitcounts = [e for e in self.orig_hitcounts]

        if self.highlight:
            self._bb_highlight(True)

        self.current_page = 0
        self.hitcount_counter.setText("Basic block count: {}".format(len(self.hitcounts)))
        self._render_nav_line()
        self._render_page()

    def _cb_diff_diff(self, item):
        new_db = _load_db(self.bv)

        if not new_db:
            return

        source_bbs = set([e[0] for e in self.hitcounts])
        new_bbs = set([e[0] for e in new_db.get_hitcounts()])
        result_bbs = source_bbs - new_bbs

        if self.highlight:
            self._bb_highlight(False)

        previous_count = len(self.hitcounts)
        self.hitcounts = list(filter(lambda e: e[0] in result_bbs, self.hitcounts))
        self.hitcount_counter.setText("Basic block count: {} (previously {})".format(len(self.hitcounts), previous_count))

        if self.highlight:
            self._bb_highlight(True)

        self.current_page = 0
        self._render_nav_line()
        self._render_page()

    def _cb_diff_inter(self, item):
        new_db = _load_db(self.bv)

        if not new_db:
            return

        source_bbs = set([e[0] for e in self.hitcounts])
        new_bbs = set([e[0] for e in new_db.get_hitcounts()])
        result_bbs = source_bbs & new_bbs

        if self.highlight:
            self._bb_highlight(False)

        previous_count = len(self.hitcounts)
        self.hitcounts = list(filter(lambda e: e[0] in result_bbs, self.hitcounts))
        self.hitcount_counter.setText("Basic block count: {} (previously {})".format(len(self.hitcounts), previous_count))

        if self.highlight:
            self._bb_highlight(True)

        self.current_page = 0
        self._render_nav_line()
        self._render_page()

    def _render_nav_line(self):
        max_pages = math.ceil(len(self.hitcounts) / BBViewerWidget.PER_PAGE_COUNT)
        self.page_count_label.setText("Page: {} / {}".format(self.current_page + 1, max_pages))

        if self.current_page == 0:
            self.back_button.setEnabled(False)
        else:
            self.back_button.setEnabled(True)

        if self.current_page == max_pages-1 or max_pages == 0:
            self.next_button.setEnabled(False)
        else:
            self.next_button.setEnabled(True)

    def _render_page(self):
        start = BBViewerWidget.PER_PAGE_COUNT * self.current_page
        hitcounts = self.hitcounts[start:start+BBViewerWidget.PER_PAGE_COUNT]

        self.hit_table.setRowCount(len(hitcounts))

        for i, e in enumerate(hitcounts):
            address_item = QTableWidgetItem("0x{:x}".format(e[0]))
            hitcount_item = QTableWidgetItem("{}".format(e[1]))
            name_item = QTableWidgetItem(_name_from_address(self.bv, e[0]))

            address_item.setFlags(Qt.ItemIsEnabled)
            hitcount_item.setFlags(Qt.ItemIsEditable)
            name_item.setFlags(Qt.ItemIsEditable)

            self.hit_table.setItem(i, 0, address_item)
            self.hit_table.setItem(i, 1, hitcount_item)
            self.hit_table.setItem(i, 2, name_item)

    def _bb_highlight(self, highlight):
        def delete_hitcount_str(input_str):
            if "(hitcount: " not in input_str:
                return input_str

            chk = input_str[input_str.find("(hitcount: "):]

            if ")\n" not in input_str:
                return input_str

            chk = chk[:input_str.find(")\n")+2]

            return input_str.replace(chk, "")

        # (0, 255, 106)
        colorHighlight = HighlightColor(red=0, green=255, blue=106)

        for bbaddr, bbhitcount in self.hitcounts:
            bbs = self.bv.get_basic_blocks_at(bbaddr)

            if not bbs:
                print("Could not find basic block at address: 0x{:x}".format(bbaddr))
                continue

            bb = bbs[0]
            fn = bb.function

            if not fn:
                print("Could not find function containing block at address: 0x{:x}".format(bbaddr))
                continue

            cur_comment = delete_hitcount_str(fn.get_comment_at(bbaddr))

            if highlight:
                bb.set_user_highlight(colorHighlight)
                fn.set_comment_at(bbaddr, "(hitcount: {})\n".format(bbhitcount) + cur_comment)
            else:
                bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
                fn.set_comment_at(bbaddr, cur_comment)
