import sqlite3
import os

class TraceDBError(Exception):
    pass

class TraceDB:
    def __init__(self, bv, dbpath):
        self.should_translate = False
        self.sqlite_handle = None

        self.map_low = -1
        self.map_high = -1

        # Getting the segment offset if needed
        self.exec_off = -1

        if len(bv.segments) == 0:
            raise DBException("No segments in file")

        if bv.segments[0].start == 0:
            self.should_translate = True

            # Does not handle multiple executable segments for now
            for seg in bv.segments:
                if seg.executable:
                    self.exec_off = seg.start
                    break

            if self.exec_off < 0:
                raise DBException("Could not find executable segment")

        # Loading the db
        self.branch_count, self.mapping_count, self.hitcount_count = self._load(dbpath)
        file_basename = os.path.basename(bv.file.original_filename)

        if self.should_translate:
            mappings = self.get_mappings()

            for m in mappings:
                if m[0].endswith(file_basename):
                    self.map_low = m[1]
                    self.map_high = m[2]
                    break

            if self.map_low < 0:
                raise DBException("Could not find matching segment in trace")

    def _load(self, dbpath):
        self.sqlite_handle = sqlite3.connect(dbpath)

        # Computing count
        c = self.sqlite_handle.cursor()

        c.execute("SELECT COUNT(*) FROM branches;")
        branch_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM mappings;")
        mapping_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM hitcounts;")
        hitcount_count = c.fetchone()[0]

        # Getting the addresses

        c.close()

        return (branch_count, mapping_count, hitcount_count)

    def _pie_to_phys(self, addr):
        if self.should_translate:
            # Should not happen but we never know
            if addr < self.map_low or addr >= self.map_high:
                return addr

            return (addr - self.map_low) + self.exec_off

        return addr

    def _phys_to_pie(self, addr):
        if self.should_translate:
            return (addr - self.exec_off) + self.map_low

        return addr

    def get_xrefs_from(self, addr):
        c = self.sqlite_handle.cursor()
        xrefs = {}
        
        for xref in c.execute("SELECT destination FROM branches WHERE source=?;", (self._phys_to_pie(addr),)):
            xref = self._pie_to_phys(xref[0])

            if xref in xrefs:
                xrefs[xref] += 1
            else:
                xrefs[xref] = 1

        c.close()
        xrefs = sorted(xrefs.items(), key=lambda a: a[1], reverse=True)

        return list(xrefs)

    def get_hitcounts(self):
        c = self.sqlite_handle.cursor()
        hitcounts = []
        
        for address, hitcount in c.execute("SELECT address,hitcount FROM hitcounts ORDER BY hitcount;"):
            hitcounts.append((self._pie_to_phys(address), hitcount))

        c.close()

        return hitcounts

    def get_mappings(self):
        c = self.sqlite_handle.cursor()
        mappings = []

        for filename, start, end in c.execute("SELECT filename, start, end FROM mappings;"):
            mappings.append((filename, start, end))

        return mappings

