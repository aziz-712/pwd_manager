# Legacy v1 prototype (superseded, kept for reference)

The original `pwd_manager`: a menu-driven CLI storing pickled records in `.pwd`
files. It is kept so the history stays legible, and it is wired into nothing.
Do not use it for real passwords.

Why v2 replaced it rather than extending it:

* **Passwords were bcrypt-hashed, not encrypted.** Hashing is one-way, so a
  stored password could never be read back. A password manager that cannot give
  you your password back is a password checker.
* **`pickle` for storage.** Unpickling executes whatever the file says, so
  opening an untrusted `.pwd` file was arbitrary code execution.
* **`random.choice` for generation.** The Mersenne Twister is not a CSPRNG; a few
  hundred characters of output are enough to reconstruct its state and predict
  every password it will ever produce.
* **Domains and metadata in the clear**, with no integrity protection at all —
  any edit to the file went undetected.

Migration: there is none, and cannot be. The v1 files hold bcrypt hashes, so the
original passwords are not recoverable from them by design. Re-enter the entries
— or better, rotate them.
