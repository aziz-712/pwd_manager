package dev.zkvault.core

/**
 * Canonical JSON, byte-compatible with Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
 *
 * This is not a convenience: canonical bytes are the AEAD associated data. If
 * this and its Python counterpart ever disagree by one byte, vaults written by
 * one client stop opening in the other -- and it will present as data corruption,
 * not as a serialisation bug. Any change here needs a cross-implementation test
 * vector (see kmp/README.md).
 */
object CanonicalJson {

    sealed interface Value
    data class S(val value: String) : Value
    data class I(val value: Long) : Value
    data class O(val entries: Map<String, Value>) : Value
    data class A(val items: List<Value>) : Value

    fun encode(value: Value): ByteArray = buildString { write(value, this) }.encodeToByteArray()

    private fun write(value: Value, out: StringBuilder) {
        when (value) {
            is S -> writeString(value.value, out)
            is I -> out.append(value.value)
            is A -> {
                out.append('[')
                value.items.forEachIndexed { i, item ->
                    if (i > 0) out.append(',')
                    write(item, out)
                }
                out.append(']')
            }
            is O -> {
                out.append('{')
                // Python's sort_keys sorts by code point; Kotlin's natural
                // String ordering matches for the BMP, which is all we emit.
                value.entries.keys.sorted().forEachIndexed { i, key ->
                    if (i > 0) out.append(',')
                    writeString(key, out)
                    out.append(':')
                    write(value.entries.getValue(key), out)
                }
                out.append('}')
            }
        }
    }

    /** Escapes exactly what Python escapes with ensure_ascii=False. */
    private fun writeString(s: String, out: StringBuilder) {
        out.append('"')
        for (ch in s) {
            when (ch) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                else ->
                    if (ch < ' ') out.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
                    else out.append(ch)
            }
        }
        out.append('"')
    }
}
