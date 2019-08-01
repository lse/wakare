import math

from .dbutils import TraceDB
from PySide2.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QSizePolicy, QCheckBox, QGroupBox
from PySide2.QtCore import Qt

from binaryninjaui import DockContextHandler, UIActionHandler
from binaryninja.highlight import HighlightColor, HighlightStandardColor

def _name_from_address(bv, address):
    fns = bv.get_functions_containing(address)

    if not fns:
        return "(unknown)"

    return fns[0].name

class XrefsDialog(QDialog):
    def __init__(self, branch_address, bv, db):
        super(XrefsDialog, self).__init__()

        # Init variables
        self.bv = bv
        self.branch_address = branch_address
        self.xref_list = db.get_xrefs_from(branch_address)
        
        # Init widgets
        self.setWindowTitle("Branch xrefs")
        self.xref_table = QTableWidget(len(self.xref_list), 3)
        self.close_button = QPushButton("Close")

        self.xref_table.setHorizontalHeaderLabels(["Address", "Hitcount", "Function"])
        self.xref_table.verticalHeader().hide()
        self.xref_table.itemDoubleClicked.connect(self._table_cb)

        for i, e in enumerate(self.xref_list):
            address_item = QTableWidgetItem("0x{:x}".format(e[0]))
            hitcount_item = QTableWidgetItem("{}".format(e[1]))
            name_item = QTableWidgetItem(_name_from_address(bv, branch_address))
            
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
        self.bv.navigate(self.bv.view, self.branch_address)
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
        vlayout.addLayout(prevnextlayout)

        self.setLayout(vlayout)

    def _cb_table(self, elem):
        addr = self.hitcounts[(BBViewerWidget.PER_PAGE_COUNT * self.current_page) + elem.row()][0]
        self.bv.navigate(self.bv.view, addr)

    def _cb_ascending(self, elem):
        self.descending = not self.descending
        self.hitcounts = sorted(self.hitcounts, key=lambda a: a[1], reverse=self.descending)
        self.current_page = 0;

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
        def delete_hitcount_str(input_str):
            if "(hitcount: " not in input_str:
                return input_str

            chk = input_str[input_str.find("(hitcount: "):]

            if ")\n" not in input_str:
                return input_str

            chk = chk[:input_str.find(")\n")+2]

            return input_str.replace(chk, "")

        # (0, 255, 106)
        self.highlight = not self.highlight
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

            if self.highlight:
                bb.set_user_highlight(colorHighlight)
                fn.set_comment_at(bbaddr, "(hitcount: {})\n".format(bbhitcount) + cur_comment)
            else:
                bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
                fn.set_comment_at(bbaddr, cur_comment)

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
