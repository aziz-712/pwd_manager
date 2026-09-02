"""zkvault blind sync server.

Blind means exactly this: the server stores an opaque byte string per user and
never parses it. There is no code path here that imports the client's vault
format, and there must never be one.
"""
