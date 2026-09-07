import pefile
import random
import struct
import math
import re

# Todo: do an overlay check, move to after section, set security directory entry if applicable
# Todo: Move bound import structure if present after last section entry
def add_section(binary, virt_size=None, raw_size=None, data=bytes(), name='.debug', charac=0xc0300040, ptr_reloc=0,
                num_reloc=0, ptr_line=0, num_line=0):
    section_header_size = pefile.Structure(pefile.PE.__IMAGE_SECTION_HEADER_format__).sizeof()
    # Todo: clean this by looking at struct file offset instead, or index with full last blob?
    pefile_new = pefile.PE(data=binary)
    sec_headers_end = pefile_new.header.index(pefile_new.sections[-1].Name) + section_header_size

    # let's assume we want the padding as well, probably won't matter since we have number of headers field, maybe we'll verify one day
    if len(pefile_new.header[sec_headers_end:]) < (2 * section_header_size):
        raise ValueError('No header space/padding available to add new section')

    if len(set(pefile_new.header[sec_headers_end:])) != 1:
        raise ValueError('Data present after last section header')

    if raw_size < len(data):
        raise ValueError('Provided data is more than raw_size')

    if not raw_size and data:
        raw_size = len(data)

    if not virt_size and data:
        virt_size = len(data)

    if not virt_size and raw_size:
        virt_size = raw_size

    if not data:
        data = bytes(raw_size)

    new_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    new_section.set_file_offset(sec_headers_end)

    virt_address = pefile_new.sections[-1].VirtualAddress + pefile_new.sections[-1].Misc_VirtualSize
    virt_address = math.ceil(
        virt_address / pefile_new.OPTIONAL_HEADER.SectionAlignment) * pefile_new.OPTIONAL_HEADER.SectionAlignment

    raw_address = pefile_new.sections[-1].PointerToRawData + pefile_new.sections[-1].SizeOfRawData
    raw_address = math.ceil(
        raw_address / pefile_new.OPTIONAL_HEADER.FileAlignment) * pefile_new.OPTIONAL_HEADER.FileAlignment
    raw_size = math.ceil(raw_size / pefile_new.OPTIONAL_HEADER.FileAlignment) * pefile_new.OPTIONAL_HEADER.FileAlignment

    image_size = virt_address + math.ceil(
        virt_size / pefile_new.OPTIONAL_HEADER.SectionAlignment) * pefile_new.OPTIONAL_HEADER.SectionAlignment

    new_section.Name = name.encode()
    new_section.Misc = virt_size
    new_section.Misc_PhysicalAddress = new_section.Misc
    new_section.Misc_VirtualSize = new_section.Misc
    new_section.VirtualAddress = virt_address
    new_section.SizeOfRawData = raw_size
    new_section.PointerToRawData = raw_address
    new_section.Characteristics = charac

    new_section.PointerToRelocations = ptr_reloc
    new_section.NumberOfRelocations = num_reloc
    new_section.PointerToLinenumbers = ptr_line
    new_section.NumberOfLinenumbers = num_line

    pefile_new.FILE_HEADER.NumberOfSections += 1
    pefile_new.OPTIONAL_HEADER.SizeOfImage = image_size
    pefile_new.__structures__.append(new_section)

    raw_exe = pefile_new.write()
    raw_exe += data + bytes(raw_size - len(data))
    raw_exe = pefile.PE(data=raw_exe)
    raw_exe.OPTIONAL_HEADER.CheckSum = raw_exe.generate_checksum()

    return raw_exe.write()


# Todo: we broke this at some point, should be passing data blob to and from, not PE object
# Note: this checks out, leave it alone, we've been over this, seriously.
# Note: this wipes all other debug directory entries
# Todo: check if we can add without new section, maybe where old structure was, also hard, since it's likely split across different debug directory types/structures
def add_codeview_debug_directory(pef, directory_name='.debug', age=1, pdb_name='test.pdb',
                                 guid='45530D6E-681D-4C44-73BD-F36D666E4E40'):
    __CV_INFO_PDB70_format__ = ['CV_INFO_PDB70',
                                ['I,CvSignature', 'I,Signature_Data1', 'H,Signature_Data2', 'H,Signature_Data3',
                                 '8s,Signature_Data4', 'I,Age']]
    __CV_INFO_PDB70_format__[1].append('{0}s,PdbFileName'.format(
        len(pdb_name) + 1))  # the size of the pdb70 entry does include the name null terminator

    debug_directory = pefile.Structure(
        pefile.PE.__IMAGE_DEBUG_DIRECTORY_format__)  # TODO: Could pass offset here instead of set_file_offset later
    pdb70_entry = pefile.Structure(
        __CV_INFO_PDB70_format__)  # TODO: Could pass offset here instead of set_file_offset later
    new_section_size = debug_directory.sizeof() + pdb70_entry.sizeof()
    pef = add_section(pef, name=directory_name, raw_size=new_section_size)

    debug_directory.set_file_offset(pef.sections[-1].PointerToRawData)
    debug_directory.Characteristics = 0
    debug_directory.TimeDateStamp = pef.FILE_HEADER.TimeDateStamp
    debug_directory.MajorVersion = 0
    debug_directory.MinorVersion = 0
    debug_directory.Type = 2
    debug_directory.SizeOfData = pdb70_entry.sizeof()
    debug_directory.AddressOfRawData = pef.sections[-1].VirtualAddress + debug_directory.sizeof()
    debug_directory.PointerToRawData = pef.sections[-1].PointerToRawData + debug_directory.sizeof()

    pdb70_entry.set_file_offset(debug_directory.PointerToRawData)
    guid = guid.split(sep='-')
    pdb70_entry.CvSignature = int.from_bytes(b'RSDS', 'little')
    pdb70_entry.Signature_Data1 = int(guid[0], 16)
    pdb70_entry.Signature_Data2 = int(guid[1], 16)
    pdb70_entry.Signature_Data3 = int(guid[2], 16)
    # silly pefile doesn't have seperate entries for these, so we merge them to stay consistent with their approach
    pdb70_entry.Signature_Data4 = bytes.fromhex(guid[3] + guid[4])
    pdb70_entry.Age = age
    pdb70_entry.PdbFileName = pdb_name.encode() + b'\x00'

    if pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress:
        for cur_exp in pef.DIRECTORY_ENTRY_DEBUG:
            pef.set_bytes_at_rva(cur_exp.struct.AddressOfRawData, bytes(cur_exp.struct.SizeOfData))
            pef.__structures__.remove(cur_exp.struct)
            if cur_exp.entry:
                pef.__structures__.remove(cur_exp.entry)
    pef.set_bytes_at_rva(
        pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress,
        bytes(pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size))

    pef.__structures__.append(debug_directory)
    pef.__structures__.append(pdb70_entry)

    pef.DIRECTORY_ENTRY_DEBUG = [pefile.DebugData()]
    pef.DIRECTORY_ENTRY_DEBUG[0].struct = debug_directory
    pef.DIRECTORY_ENTRY_DEBUG[0].entry = pdb70_entry

    pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress = \
        pef.sections[-1].VirtualAddress
    pef.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size = debug_directory.sizeof()

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef


class CustomExportDirectoryError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Dummy:

    def __len__(self):
        return 4096


class CustomExportDirectoryEntry:

    def __init__(self, orig_ord=None, orig_name=None, fwd_ord=None, fwd_name=None, fwd_address=None, fwd_mod=None):
        if fwd_address and fwd_mod:
            raise CustomExportDirectoryError('New export entry can specify only one of new_address or fwd_mod')
        if not (orig_ord or orig_name):
            raise CustomExportDirectoryError('New export entry must specify at least orig_ord or orig_name')
        if fwd_mod and not (fwd_ord or fwd_name):
            raise CustomExportDirectoryError('Forwarded export must specify either fwd_ord or fwd_name')
        if len([x for x in [fwd_ord, fwd_name, fwd_address] if x]) > 1:
            raise CustomExportDirectoryError(
                'New export entry can specify only one of fwd_ord, fwd_name, or fwd_address')

        self.orig_name = orig_name.encode() if orig_name and not type(orig_name) == bytes else orig_name
        self.fwd_name = fwd_name.encode() if fwd_name and not type(fwd_name) == bytes else fwd_name
        self.fwd_mod = fwd_mod.encode() if fwd_mod and not type(fwd_mod) == bytes else fwd_mod

        self.orig_ord = orig_ord
        self.fwd_ord = fwd_ord
        self.fwd_address = fwd_address
        self.name_ord_index = None


class CustomExportDirectory:

    def __init__(self, binary=None, module_name=None, base=1, time_date_stamp=0, major_version=0, minor_version=0,
                 name='',
                 characteristics=0, forward_path=None):
        self.export_dir = pefile.Structure(pefile.PE.__IMAGE_EXPORT_DIRECTORY_format__)
        self.characteristics = characteristics
        self.time_date_stamp = time_date_stamp
        self.major_version = major_version
        self.minor_version = minor_version
        self.name = name.encode()
        self.base = base
        self.exports = []
        self.export_entries = []
        self.cur_iter = None
        self.name_count = None
        self.name_ord_count = None
        self.names_len = None
        self.forward_count = None
        self.forward_len = None
        self.name_ord_index = None

        if binary and (
                module_name is not None or base != 1 or time_date_stamp != 0 or major_version != 0 or minor_version != 0 or characteristics != 0):
            raise CustomExportDirectoryError('Additional parameters cannot be specified with binary')

        if binary:
            self._clone_from_file(binary, forward_path)

    def __len__(self):
        pass

    def _iter_(self):
        if self.cur_iter is not None:
            raise CustomExportDirectoryError('Iterator state error, already active')
        self.cur_iter = 0
        return self

    def __next__(self):
        self.cur_iter += 1
        if self.cur_iter > len(self.exports):
            self.cur_iter = None
            raise StopIteration
        return self.exports[self.cur_iter - 1]

    def _clone_from_file(self, binary, forward_path):
        forward_clone = pefile.PE(data=binary)

        self.characteristics = forward_clone.DIRECTORY_ENTRY_EXPORT.struct.Characteristics
        self.time_date_stamp = forward_clone.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp
        self.major_version = forward_clone.DIRECTORY_ENTRY_EXPORT.struct.MajorVersion
        self.minor_version = forward_clone.DIRECTORY_ENTRY_EXPORT.struct.MinorVersion
        self.base = forward_clone.DIRECTORY_ENTRY_EXPORT.struct.Base
        self.name = forward_clone.DIRECTORY_ENTRY_EXPORT.name

        for cur_export in forward_clone.DIRECTORY_ENTRY_EXPORT.symbols:
            if forward_path:
                fwd_ordinal = cur_export.ordinal
                if cur_export.name:
                    fwd_ordinal = None
                self.add_export(orig_ord=cur_export.ordinal, fwd_ord=fwd_ordinal, orig_name=cur_export.name,
                                fwd_name=cur_export.name, fwd_mod=forward_path[:-4])
            else:
                self.add_export(orig_ord=cur_export.ordinal, orig_name=cur_export.name, fwd_address=cur_export.address)

        forward_clone.close()

    def _format_exports(self):
        if len(set([x.orig_ord for x in self.exports if x.orig_ord])) != len(self.exports):
            raise CustomExportDirectoryError('Duplicate or missing ordinal number')
        self.exports = sorted(self.exports, key=lambda d: d.orig_ord)
        if self.exports[0].orig_ord != self.base:
            raise CustomExportDirectoryError('First exported ordinal does not match ordinal base')
        for ord_index in range(len(self.exports) - 1):
            if self.exports[ord_index].orig_ord != self.exports[ord_index + 1].orig_ord - 1:
                dummy_export_count = self.exports[ord_index + 1].orig_ord - self.exports[ord_index].orig_ord
                for dummy_ordinal in range(1, dummy_export_count):
                    self.add_export(orig_ord=self.exports[ord_index].orig_ord + dummy_ordinal, fwd_address=0)
        self.exports = sorted(self.exports, key=lambda d: d.orig_ord)
        for cur_export in self.exports:
            if cur_export.fwd_mod:
                cur_export.fwd_name = (cur_export.fwd_mod + b'.' + cur_export.fwd_name) if cur_export.fwd_name else (
                        cur_export.fwd_mod + b'.#' + bytes(str(cur_export.fwd_ord).encode()))
        sorted_name_exports = sorted([x for x in self.exports if x.orig_name], key=lambda d: d.orig_name)
        for cur_export in sorted_name_exports:
            cur_export.name_ord_index = sorted_name_exports.index(cur_export)
        if len(set([x.orig_name for x in self.exports if x.orig_name])) != len(sorted_name_exports):
            raise CustomExportDirectoryError('Duplicate export names')

    def _find_export(self, orig_ord, orig_name):
        orig_name = orig_name.encode() if orig_name and not type(orig_name) == bytes else orig_name
        if not (orig_ord or orig_name) or (orig_ord and orig_name):
            raise CustomExportDirectoryError('Must specify either orig_ord or orig_name')
        remove_export = [x for x in self.exports if x.orig_ord == orig_ord or x.orig_name == orig_name]
        if len(remove_export) == 0:
            raise CustomExportDirectoryError('Unable to find export')
        elif len(remove_export) > 1:
            print([x.orig_name for x in remove_export])
            raise CustomExportDirectoryError('Multiple exports matching the criteria exist')
        return remove_export[0]

    def sizeof(self):
        self.name_count = self.name_ord_count = len([x for x in self.exports if x.orig_name])
        self.names_len = sum(
            [len(x.orig_name) for x in self.exports if x.orig_name]) + self.name_count  # remember null terminator
        self.forward_count = len([x for x in self.exports if x.fwd_name])
        self.forward_len = sum(
            [len(x.fwd_name) for x in self.exports if x.fwd_name]) + self.forward_count  # remember null terminator
        return self.export_dir.sizeof() + len(self.name) + 1 + ((len(self.exports) + self.name_count) * 4) + (
                self.name_ord_count * 2) + self.names_len + self.forward_len
        # struct size, dll name len, address of functions array size, address of names array size, name ordinals array size, func names len,

    # Todo: check if we can use existing export dir space
    def apply(self, binary, unmangle=False):
        if unmangle:
            for cur_export in self.exports:
                cur_export.orig_name = re.match(b'[^@]+', cur_export.orig_name)[0] if cur_export.orig_name else None

        self._format_exports()
        pefile_new = add_section(binary, raw_size=self.sizeof(), name='.edata')
        pefile_new = pefile.PE(data=pefile_new)
        self.export_dir.set_file_offset(pefile_new.sections[-1].PointerToRawData)
        pefile_new.__structures__.append(self.export_dir)

        addr_func = pefile_new.sections[-1].PointerToRawData + self.export_dir.sizeof()
        addr_names = addr_func + (len(self.exports) * 4)
        addr_name_ordinals = (addr_names + self.name_count * 4)
        addr_name_str = (addr_name_ordinals + self.name_count * 2)
        addr_next_name_entry = addr_name_str + len(self.name) + 1
        addr_next_forward_entry = addr_next_name_entry + self.names_len

        pefile_new.set_bytes_at_offset(addr_name_str, self.name + b'\x00')
        self.export_dir.Name = pefile_new.get_rva_from_offset(addr_name_str)
        self.export_dir.Base = self.base
        self.export_dir.NumberOfFunctions = len(self.exports)
        self.export_dir.NumberOfNames = self.name_count
        self.export_dir.AddressOfFunctions = pefile_new.get_rva_from_offset(addr_func)
        self.export_dir.AddressOfNames = pefile_new.get_rva_from_offset(addr_names)
        self.export_dir.AddressOfNameOrdinals = pefile_new.get_rva_from_offset(addr_name_ordinals)
        self.export_dir.Characteristics = self.characteristics
        self.export_dir.TimeDateStamp = self.time_date_stamp
        self.export_dir.MajorVersion = self.major_version
        self.export_dir.MinorVersion = self.minor_version

        for cur_export in self.exports:
            new_export_entry = pefile.ExportData()
            new_export_entry.pe = pefile_new
            new_export_entry.ordinal = new_export_entry.address = new_export_entry.forwarder = new_export_entry.name = Dummy()
            if cur_export.orig_name:
                pefile_new.set_dword_at_offset(addr_names + (cur_export.name_ord_index * 4),
                                               pefile_new.get_rva_from_offset(addr_next_name_entry))
                new_export_entry.name_offset = addr_next_name_entry  # internal name
                addr_next_name_entry += len(cur_export.orig_name) + 1
                new_export_entry.name = cur_export.orig_name + b'\x00'  # internal name
                new_export_entry.ordinal_offset = addr_name_ordinals + (cur_export.name_ord_index * 2)  # internal name
                new_export_entry.ordinal = self.exports.index(cur_export)  # internal entry
            new_export_entry.address_offset = addr_func + self.exports.index(
                cur_export) * 4  # internal name, offset to address of func or forward name
            if cur_export.fwd_name:
                new_export_entry.forwarder_offset = addr_next_forward_entry  # internal entry, file offset for next export name, written to below
                new_export_entry.address = pefile_new.get_rva_from_offset(
                    addr_next_forward_entry)  # internal name, address that points back into export dir, if not fwd, would be addr of func
                addr_next_forward_entry += len(cur_export.fwd_name) + 1
                new_export_entry.forwarder = cur_export.fwd_name + b'\x00'  # internal name, name of forward, written to forwarder_offset above
            else:
                new_export_entry.address = cur_export.fwd_address
            self.export_entries += [new_export_entry]

        #wipe the existing entry? doesn't update OPTIONAL_HEADER data here, does it below
        if pefile_new.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress:
            pefile_new.set_bytes_at_rva(pefile_new.OPTIONAL_HEADER.DATA_DIRECTORY[
                                            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress,
                                        bytes(
                                            pefile_new.OPTIONAL_HEADER.DATA_DIRECTORY[
                                                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size))
            pefile_new.__structures__.remove(pefile_new.DIRECTORY_ENTRY_EXPORT.struct)

        #there might not be an export directory, so we need to add it
        try:
            pefile_new.DIRECTORY_ENTRY_EXPORT.name = self.name
            pefile_new.DIRECTORY_ENTRY_EXPORT.struct = self.export_dir
            pefile_new.DIRECTORY_ENTRY_EXPORT.symbols = self.export_entries
        except AttributeError:
            pefile_new.DIRECTORY_ENTRY_EXPORT = pefile.ExportDirData(stuct=self.export_dir, symbols=self.export_entries, name=self.name)

        pefile_new.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress = \
            pefile_new.sections[-1].VirtualAddress
        pefile_new.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size = self.sizeof()

        pefile_new.OPTIONAL_HEADER.CheckSum = pefile_new.generate_checksum()
        return pefile_new.write()

    def add_export(self, orig_ord=None, orig_name=None, fwd_ord=None, fwd_name=None, fwd_address=None, fwd_mod=None):
        if not orig_ord:
            orig_ord = len(self.exports) - self.base + 2
        self.exports += [
            CustomExportDirectoryEntry(orig_ord=orig_ord, orig_name=orig_name, fwd_ord=fwd_ord, fwd_name=fwd_name,
                                       fwd_address=fwd_address, fwd_mod=fwd_mod)]

    def remove_export(self, orig_ord=None, orig_name=None):
        if self.cur_iter is not None:
            raise CustomExportDirectoryError('Cannot remove member with active iterator')
        self.exports.remove(self._find_export(orig_ord, orig_name))

    def rename_export(self, orig_ord=None, orig_name=None, new_name=None):
        if orig_name == new_name:
            raise CustomExportDirectoryError('Export entry orig_name and new_name can\'t match')
        change_export = self._find_export(orig_ord, orig_name)
        change_export.orig_name = new_name.encode()

    def change_forward(self, orig_ord=None, orig_name=None, fwd_ord=None, fwd_name=None, fwd_address=None,
                       fwd_mod=None):
        change_export = self._find_export(orig_ord, orig_name)
        if fwd_address and fwd_mod:
            raise CustomExportDirectoryError('Export entry can specify only one of fwd_address or fwd_mod')
        if len([x for x in [fwd_ord, fwd_name, fwd_address] if x]) > 1:
            raise CustomExportDirectoryError('Export entry can specify only one of fwd_ord or fwd_name')
        change_export.fwd_ord = fwd_ord
        change_export.fwd_name = fwd_name
        change_export.fwd_address = fwd_address
        change_export.fwd_mod = fwd_mod


def remove_overlay(pef):
    pass


def add_overlay(pef, data):
    pass

def clear_relocations(pef, start_rva, stop_rva):
    pass


def find_raw_cave(pef, size=None):
    pass


def find_virtual_cave(pef):
    pass


def remove_relocations(pef, start_rva, stop_rva):
    pass


def add_relocation(pef, reloc_rva):
    pass

# Note: yeah, not gonna happen, SectionAlignment vs FileAlignment makes this really hard, would have to change raw size to match virtual for section, fix up all following
# sections, and update all references to following sections
def consume_next_section(pef, section_name):
    pass


# Note: wonder if it's possible to add import to already included dll without mucking up the IAT, will win allow two IAT arrays for a single DLL
def add_import():
    pass


def randomize_time(binary, start=1451610061, end=1483232461):
    pef = pefile.PE(data=binary)

    timestamp = random.randrange(start, end)
    pef.FILE_HEADER.TimeDateStamp = timestamp
    try:
        pef.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp = timestamp
    except AttributeError:
        pass
    try:
        pef.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp = timestamp
    except AttributeError:
        pass

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef.write()


def import_shuffle(binary):
    pef = pefile.PE(data=binary)

    import_entry_locations = [x.struct.get_file_offset() for x in pef.DIRECTORY_ENTRY_IMPORT]
    random.shuffle(import_entry_locations)

    for cur_entry in pef.DIRECTORY_ENTRY_IMPORT:
        cur_entry.struct.set_file_offset(import_entry_locations.pop())

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef.write()


def patch_start(binary, payload_marker, payload_data):
    pef = pefile.PE(data=binary)

    payload_marker = bytes.fromhex(payload_marker)
    original_entry_offset = pef.get_offset_from_rva(pef.OPTIONAL_HEADER.AddressOfEntryPoint)

    marker_data_offset = pef.__data__.find(payload_marker)
    if marker_data_offset == -1:
        raise pefile.PEFormatError('Error processing marker, marker not found')

    second_marker_offset = pef.__data__[marker_data_offset + len(payload_marker):].find(payload_marker)
    if second_marker_offset != -1:
        raise pefile.PEFormatError('Error processing marker, multiple markers found')

    pef.OPTIONAL_HEADER.AddressOfEntryPoint = pef.get_rva_from_offset(marker_data_offset)
    pef.set_bytes_at_offset(marker_data_offset, payload_data)
    marker_entry_offset = original_entry_offset - marker_data_offset - len(payload_data) - 5
    jump_offset = struct.pack('i', marker_entry_offset)

    pef.set_bytes_at_offset(marker_data_offset + len(payload_data), b'\xE9' + jump_offset)

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef.write()


def append_certificate(binary, certificate):
    pef = pefile.PE(data=binary)

    overlay_address = pef.sections[-1].PointerToRawData + pef.sections[-1].SizeOfRawData
    #Uhm, I think this is wrong - if binary_data_thing[overlay_address:] != b'':
    if len(certificate) > overlay_address:
        raise pefile.PEFormatError('Overlay data present, which is not compatible with certificate')

    pef.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = overlay_address
    pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = len(certificate)

    return pef.write() + certificate

def remove_tls(binary):
    pef = pefile.PE(data=binary)

    #Should we be removing the TLS data?
    pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']].VirtualAddress = 0
    pef.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']].Size = 0

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef.write()

def fix_zero_section_size(binary):
    pef = pefile.PE(data=binary)

    for section in pef.sections:
        if section.SizeOfRawData == 0:
            section.SizeOfRawData = math.ceil(section.Misc_VirtualSize / pef.OPTIONAL_HEADER.FileAlignment) * pef.OPTIONAL_HEADER.FileAlignment

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef.write()

def rename_section(binary, old_name, new_name):
    pef = pefile.PE(data=binary)

    for section in pef.sections:
        if section.Name.decode().rstrip('\x00') == old_name:
            section.Name = new_name.encode()

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    return pef.write()

def exe_to_dll(binary):
    pef = pefile.PE(data=binary)

    original_entry_rva = pef.OPTIONAL_HEADER.AddressOfEntryPoint

    code_section = 0
    for section_index in range(len(pef.sections)):
        if pef.sections[section_index].contains_rva(original_entry_rva):
            break
        code_section += 1
    else:
        raise pefile.PEFormatError('Could not find code section')

    new_entry_rva = pef.sections[code_section].VirtualAddress + pef.sections[code_section].SizeOfRawData - 6
    pef.set_bytes_at_rva(new_entry_rva, b'\xB8\x01\x00\x00\x00\xC3')

    pef.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_rva

    pef.FILE_HEADER.Characteristics |= pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"]

    pef.OPTIONAL_HEADER.CheckSum = pef.generate_checksum()
    
    return pef.write()
