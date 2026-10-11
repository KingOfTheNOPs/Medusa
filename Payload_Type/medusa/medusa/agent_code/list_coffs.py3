    def list_coffs(self, task_id):
        import hashlib, json
        store = self._coff_store if hasattr(self, "_coff_store") else {}
        return json.dumps([{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                           for name, data in sorted(store.items())])
