eest-fuzz
=========

Library and tools for (de)structuring [EEST] data types from arbitrary byte
streams.

[EEST]: https://github.com/ethereum/execution-spec-tests/

## Entrypoints

This package provides the following entrypoints:

 - `eest-fuzz-structure <input>`
   - Given a corpus file, output structured JSON.
 - `esst-fuzz-destructure <input-dir> <output-dir>`
   - Given structured JSON, output a corpus file.
 - `eest-fuzz-self ...`
   - Start an [atheris] session, instrumenting this library. See [LibFuzzer]
     for command line options.
 - `eest-fuzz-eels ...`
   - Start an [atheris] session, instrumenting [EELS]. See [LibFuzzer] for
     command line options.

[EELS]: https://github.com/ethereum/execution-specs/
[LibFuzzer]: https://llvm.org/docs/LibFuzzer.html#options
[atheris]: https://github.com/google/atheris
