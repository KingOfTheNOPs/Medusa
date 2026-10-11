    def unregister_coff(self, task_id, coff_name):
        if not hasattr(self, "_coff_store") or coff_name not in self._coff_store:
            raise ValueError("COFF '{}' is not registered".format(coff_name))
        old = self._coff_store.pop(coff_name)
        old[:] = b"\x00" * len(old)
        return "Unregistered {}".format(coff_name)
