# Berkeley SoftFloat subset for CPU experiments

Unmodified source files from Release 3e, downloaded from the author's site:
https://www.jhauser.us/arithmetic/SoftFloat-3e.zip

Archive SHA-256:
`21130ce885d35c1fe73fc1e1bf2244178167e05c6747cad5f450cc991714c746`.

`manifest.json` lists the exact retained files and their hashes. Only the
binary32/binary64 add, subtract, multiply, divide and square-root dependency
closure is compiled. The `8086-SSE` specialization specifies x86 NaN propagation
and default NaN values. The upstream little-endian GCC/Clang platform header
uses compiler integer builtins, including `__int128`, on both host architectures.
Builds define `THREAD_LOCAL=_Thread_local`, so SoftFloat control/status globals
are thread-local. The adapter also saves/restores them per lane operation.

This library is used only by the synthetic AOT experiment, not by the game
runtime or GPU renderer. No download is needed to reproduce that experiment.

The upstream BSD license is retained in `COPYING.txt` and each source file.
