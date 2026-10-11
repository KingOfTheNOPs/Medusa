+++
title = "register_coff"
chapter = false
weight = 100
hidden = false
+++

## Summary

Downloads an AMD64 BOF into Medusa's memory for subsequent `execute_coff`
tasking by name. The cache accepts at most 32 objects of up to 2 MiB each.
Replacing or unregistering an object overwrites its mutable buffer before
releasing it.

This command can itself be introduced using `load register_coff`, so the
initial payload does not include BOF functionality.
