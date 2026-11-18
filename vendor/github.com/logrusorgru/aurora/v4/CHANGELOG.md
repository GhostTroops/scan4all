Changes
=======

---
14:15:14
Thursday, October 8, 2022

New version v4. Breaking changes. [Migrate from v3](#migrate-from-v3).

- Drop deprecated `Bleach` methods. Use `Reset` or `Clear` instead.
- Drop deprecated `Brows` and `BgBrows` methods, and `BrownFg` and `BrownBg`
  colors. Use `Yellow` variants instead.
- Instead of `Aurora` interface introduced `Aurora` structure.
- Instead of `Value` interface introduced `Value` structure.
- Implemented [hyperlinks feature](https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda).
  - added `Hyperlink` method
  - added `HyperlinkTarget` and `HyperlinkParams` methods
  - added `HyperlinkParam` type, `IsValidHyperlinkTarget`,
    `IsValidHyperlinkParam`, `HyperlinkID`, `HyperlinkEscape`,
    `HyperlinkUnescape` helper functions.
- Introduced `Config` and related functions and methods, such as `NewConfig`,
  `WithColors`, `WithHyperlinks`.
- Removed `NewAurora` function, new function `New` introduced.
- Introduced global `DefaultColorizer` that used by package root methods.
- `Sprintf` method now belongs to a colorizer and depends on its configurations.
  For package root `Sprintf` it's the `DefaultColorizer`.

Performance for all methods is almost the same. But for color- and
format-methods `aurora` now takes less allocations. But, unfortunately, for
`Sprintf` it takes more allocations.

###### Migrate from v3

1. Use `Reset` or `Clear` instead of `Bleach`.
2. Use `Yellow` instead of `Brows`.
3. Use `BgYellow` instead of `BgBrown`.
4. Use `YellowFg` instead of `BrownFg`.
5. Use `YellowBg` instead of `BrownBg`.
6. Use `New` instead of `NewAurora`.
7. Use `New(WithColors(false))` to disable colors.
8. Use `New(WithHyperlinks(false))` to disable hyperlinks.

---
16:05:02
Thursday, July 2, 2020

Change license from the WTFPL to the Unlicense due to pkg.go.dev restriction.

---
15:39:40
Wednesday, April 17, 2019

- Bright background and foreground colors
- 8-bit indexed colors `Index`, `BgIndex`
- 24 grayscale colors `Gray`, `BgGray`
- `Yellow` and `BgYellow` methods, mark Brow and BgBrown as deprecated
  Following specifications, correct name of the colors are yellow, but
  by historical reason they are called brown. Both, the `Yellow` and the
  `Brown` methods (including `Bg+`) represents the same colors. The Brown
  are leaved for backward compatibility until Go modules production release.
- Additional formats
  + `Faint` that is opposite to the `Bold`
  + `DoublyUnderline`
  + `Fraktur`
  + `Italic`
  + `Underline`
  + `SlowBlink` with `Blink` alias
  + `RapidBlink`
  + `Reverse` that is alias for the `Inverse`
  + `Conceal` with `Hidden` alias
  + `CrossedOut` with `StrikeThrough` alias
  + `Framed`
  + `Encircled`
  + `Overlined`
- Add AUTHORS.md file and change all copyright notices.
- `Reset` method to create clear value. `Reset` method that replaces
  `Bleach` method. The `Bleach` method was marked as deprecated.

---

14:25:49
Friday, August 18, 2017

- LICENSE.md changed to LICENSE
- fix email in README.md
- add "no warranty" to README.md
- set proper copyright date

---

16:59:28
Tuesday, November 8, 2016

- Rid out off sync.Pool
- Little optimizations (very little)
- Improved benchmarks

---
