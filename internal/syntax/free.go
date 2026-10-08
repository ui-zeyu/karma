// free pseudo-lexer: free(1)'s memory table.
//
// Its header is lowercase ("total used free …"), so the table styler's
// all-caps test never recognizes the line, and the fallback word-by-word cycle
// would give the same column a different color on each data row: "Swap:" carries
// three cells where "Mem:" carries six. The header is anchored here instead,
// with its leading blank run as the first anchor — the label column ("Mem:",
// "Swap:") sits to the left of the first header word and is a column of its own.

package syntax

// freeHeader anchors free's columns: each capture group is one anchor, and the
// first of them is the blank run the label column occupies.
var freeHeader = compile(`^(\s*)(total)\s+(used)\s+(free)\s+(shared)\s+(buff/cache)\s+(available)`)
