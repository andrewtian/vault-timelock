# Third-party notices

This project is GPL-3.0-only (see `LICENSE`). The files below are vendored from other projects and keep
their own licences.

## `broadcast/vendor/eff_large_wordlist.txt`

The EFF large wordlist for passphrases, by the Electronic Frontier Foundation (https://www.eff.org/dice),
licensed under Creative Commons Attribution 3.0 United States (CC BY 3.0 US,
https://creativecommons.org/licenses/by/3.0/us/). Used unmodified.

## `web/src/styles/shadcn-tailwind.css`

Copied verbatim (below its header comment) from the `shadcn` npm package, `dist/tailwind.css`
(https://github.com/shadcn-ui/ui).

```
MIT License

Copyright (c) 2023 shadcn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## npm dependencies

Dependencies installed by `npm ci` are not vendored here and keep their own licences. A page build bundles
some of them, among them GPL-3.0 code in the Privacy Cash worker (snarkjs, ffjavascript and others) and
`rpc-websockets` (LGPL-3.0).
