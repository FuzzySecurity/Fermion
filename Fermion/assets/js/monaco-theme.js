/////////////////////////////////
// Themes come from here:
// ~~> https://github.com/brijeshb42/monaco-themes
/////////////////////////////////
// Note:
// I made small background color changes
// to "idleFingers" & "Katzenmilch".
/////////////////////////////////

// idleFingers
const idleFingers = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
	  {
		"foreground": "ffffff",
		"token": "text"
	  },
	  {
		"foreground": "cdcdcd",
		"background": "282828",
		"token": "source"
	  },
	  {
		"foreground": "bc9458",
		"fontStyle": "italic",
		"token": "comment"
	  },
	  {
		"foreground": "ffe5bb",
		"token": "meta.tag"
	  },
	  {
		"foreground": "ffe5bb",
		"token": "declaration.tag"
	  },
	  {
		"foreground": "ffe5bb",
		"token": "meta.doctype"
	  },
	  {
		"foreground": "ffc66d",
		"token": "entity.name"
	  },
	  {
		"foreground": "fff980",
		"token": "source.ruby entity.name"
	  },
	  {
		"foreground": "b7dff8",
		"token": "variable.other"
	  },
	  {
		"foreground": "cccc33",
		"token": "support.class.ruby"
	  },
	  {
		"foreground": "6c99bb",
		"token": "constant"
	  },
	  {
		"foreground": "6c99bb",
		"token": "support.constant"
	  },
	  {
		"foreground": "cc7833",
		"token": "keyword"
	  },
	  {
		"foreground": "d0d0ff",
		"token": "other.preprocessor.c"
	  },
	  {
		"fontStyle": "italic",
		"token": "variable.parameter"
	  },
	  {
		"foreground": "ffffff",
		"background": "575757",
		"token": "source comment.block"
	  },
	  {
		"foreground": "a5c261",
		"token": "string"
	  },
	  {
		"foreground": "aaaaaa",
		"token": "string constant.character.escape"
	  },
	  {
		"foreground": "000000",
		"background": "cccc33",
		"token": "string.interpolated"
	  },
	  {
		"foreground": "cccc33",
		"token": "string.regexp"
	  },
	  {
		"foreground": "cccc33",
		"token": "string.literal"
	  },
	  {
		"foreground": "787878",
		"token": "string.interpolated constant.character.escape"
	  },
	  {
		"fontStyle": "underline",
		"token": "entity.name.class"
	  },
	  {
		"fontStyle": "italic underline",
		"token": "entity.other.inherited-class"
	  },
	  {
		"foreground": "b83426",
		"token": "support.function"
	  },
	  {
		"foreground": "6ea533",
		"token": "markup.list.unnumbered.textile"
	  },
	  {
		"foreground": "6ea533",
		"token": "markup.list.numbered.textile"
	  },
	  {
		"foreground": "c2c2c2",
		"fontStyle": "bold",
		"token": "markup.bold.textile"
	  },
	  {
		"foreground": "ffffff",
		"background": "ff0000",
		"token": "invalid"
	  },
	  {
		"foreground": "323232",
		"background": "fff980",
		"token": "collab.user1"
	  }
	],
	"colors": {
	  "editor.foreground": "#FFFFFF",
	  "editor.background": "#464646",
	  "editor.selectionBackground": "#5A647E",
	  "editor.lineHighlightBackground": "#353637",
	  "editorCursor.foreground": "#91FF00",
	  "editorWhitespace.foreground": "#404040"
	}
  }

// Cobalt
const Cobalt = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
		{
			"foreground": "e1efff",
			"token": "punctuation - (punctuation.definition.string | punctuation.definition.comment)"
		},
		{
			"foreground": "ff628c",
			"token": "constant"
		},
		{
			"foreground": "ffdd00",
			"token": "entity"
		},
		{
			"foreground": "ff9d00",
			"token": "keyword"
		},
		{
			"foreground": "ffee80",
			"token": "storage"
		},
		{
			"foreground": "3ad900",
			"token": "string -string.unquoted.old-plist -string.unquoted.heredoc"
		},
		{
			"foreground": "3ad900",
			"token": "string.unquoted.heredoc string"
		},
		{
			"foreground": "0088ff",
			"fontStyle": "italic",
			"token": "comment"
		},
		{
			"foreground": "80ffbb",
			"token": "support"
		},
		{
			"foreground": "cccccc",
			"token": "variable"
		},
		{
			"foreground": "ff80e1",
			"token": "variable.language"
		},
		{
			"foreground": "ffee80",
			"token": "meta.function-call"
		},
		{
			"foreground": "f8f8f8",
			"background": "800f00",
			"token": "invalid"
		},
		{
			"foreground": "ffffff",
			"background": "223545",
			"token": "text source"
		},
		{
			"foreground": "ffffff",
			"background": "223545",
			"token": "string.unquoted.heredoc"
		},
		{
			"foreground": "ffffff",
			"background": "223545",
			"token": "source source"
		},
		{
			"foreground": "80fcff",
			"fontStyle": "italic",
			"token": "entity.other.inherited-class"
		},
		{
			"foreground": "9eff80",
			"token": "string.quoted source"
		},
		{
			"foreground": "80ff82",
			"token": "string constant"
		},
		{
			"foreground": "80ffc2",
			"token": "string.regexp"
		},
		{
			"foreground": "edef7d",
			"token": "string variable"
		},
		{
			"foreground": "ffb054",
			"token": "support.function"
		},
		{
			"foreground": "eb939a",
			"token": "support.constant"
		},
		{
			"foreground": "ff1e00",
			"token": "support.type.exception"
		},
		{
			"foreground": "8996a8",
			"token": "meta.preprocessor.c"
		},
		{
			"foreground": "afc4db",
			"token": "meta.preprocessor.c keyword"
		},
		{
			"foreground": "73817d",
			"token": "meta.sgml.html meta.doctype"
		},
		{
			"foreground": "73817d",
			"token": "meta.sgml.html meta.doctype entity"
		},
		{
			"foreground": "73817d",
			"token": "meta.sgml.html meta.doctype string"
		},
		{
			"foreground": "73817d",
			"token": "meta.xml-processing"
		},
		{
			"foreground": "73817d",
			"token": "meta.xml-processing entity"
		},
		{
			"foreground": "73817d",
			"token": "meta.xml-processing string"
		},
		{
			"foreground": "9effff",
			"token": "meta.tag"
		},
		{
			"foreground": "9effff",
			"token": "meta.tag entity"
		},
		{
			"foreground": "9effff",
			"token": "meta.selector.css entity.name.tag"
		},
		{
			"foreground": "ffb454",
			"token": "meta.selector.css entity.other.attribute-name.id"
		},
		{
			"foreground": "5fe461",
			"token": "meta.selector.css entity.other.attribute-name.class"
		},
		{
			"foreground": "9df39f",
			"token": "support.type.property-name.css"
		},
		{
			"foreground": "f6f080",
			"token": "meta.property-group support.constant.property-value.css"
		},
		{
			"foreground": "f6f080",
			"token": "meta.property-value support.constant.property-value.css"
		},
		{
			"foreground": "f6aa11",
			"token": "meta.preprocessor.at-rule keyword.control.at-rule"
		},
		{
			"foreground": "edf080",
			"token": "meta.property-value support.constant.named-color.css"
		},
		{
			"foreground": "edf080",
			"token": "meta.property-value constant"
		},
		{
			"foreground": "eb939a",
			"token": "meta.constructor.argument.css"
		},
		{
			"foreground": "f8f8f8",
			"background": "000e1a",
			"token": "meta.diff"
		},
		{
			"foreground": "f8f8f8",
			"background": "000e1a",
			"token": "meta.diff.header"
		},
		{
			"foreground": "f8f8f8",
			"background": "4c0900",
			"token": "markup.deleted"
		},
		{
			"foreground": "f8f8f8",
			"background": "806f00",
			"token": "markup.changed"
		},
		{
			"foreground": "f8f8f8",
			"background": "154f00",
			"token": "markup.inserted"
		},
		{
			"background": "8fddf6",
			"token": "markup.raw"
		},
		{
			"background": "004480",
			"token": "markup.quote"
		},
		{
			"background": "130d26",
			"token": "markup.list"
		},
		{
			"foreground": "c1afff",
			"fontStyle": "bold",
			"token": "markup.bold"
		},
		{
			"foreground": "b8ffd9",
			"fontStyle": "italic",
			"token": "markup.italic"
		},
		{
			"foreground": "c8e4fd",
			"background": "001221",
			"fontStyle": "bold",
			"token": "markup.heading"
		}
	],
	"colors": {
		"editor.foreground": "#FFFFFF",
		"editor.background": "#002240",
		"editor.selectionBackground": "#B36539",
		"editor.lineHighlightBackground": "#000000",
		"editorCursor.foreground": "#FFFFFF",
		"editorWhitespace.foreground": "#FFFFFF"
	}
}

// Merbivore-Soft
const MerbivoreSoft = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
		{
			"foreground": "ac4bb8",
			"fontStyle": "italic",
			"token": "comment"
		},
		{
			"foreground": "ffffff",
			"background": "fe3838",
			"token": "invalid.deprecated"
		},
		{
			"foreground": "fc803a",
			"token": "keyword"
		},
		{
			"foreground": "fc803a",
			"token": "storage"
		},
		{
			"foreground": "c984cd",
			"token": "entity.other.inherited-class"
		},
		{
			"foreground": "7fc578",
			"token": "constant.numeric"
		},
		{
			"foreground": "68c1d8",
			"token": "constant"
		},
		{
			"foreground": "e1c582",
			"token": "constant.language"
		},
		{
			"foreground": "8ec65f",
			"token": "string"
		},
		{
			"foreground": "8ec65f",
			"token": "constant.library"
		},
		{
			"foreground": "68c1d8",
			"token": "support.type"
		},
		{
			"foreground": "8ec65f",
			"token": "support.constant"
		},
		{
			"foreground": "fc803a",
			"token": "meta.tag"
		},
		{
			"foreground": "fc803a",
			"token": "declaration.tag"
		},
		{
			"foreground": "fc803a",
			"token": "entity.name.tag"
		},
		{
			"foreground": "ac4bb8",
			"fontStyle": "italic",
			"token": "meta"
		},
		{
			"foreground": "eaf1a3",
			"token": "entity.other.attribute-name"
		},
		{
			"foreground": "ffffff",
			"background": "fe3838",
			"token": "invalid"
		},
		{
			"foreground": "b3e5b4",
			"token": "constant.character.escaped"
		},
		{
			"foreground": "b3e5b4",
			"token": "constant.character.escape"
		},
		{
			"foreground": "b3e5b4",
			"token": "string source"
		},
		{
			"foreground": "b3e5b4",
			"token": "string source.ruby"
		},
		{
			"foreground": "e6e1dc",
			"background": "6fc58b",
			"token": "markup.inserted"
		},
		{
			"foreground": "e6e1dc",
			"background": "ac3735",
			"token": "markup.deleted"
		},
		{
			"background": "5a9ee1",
			"token": "meta.diff.header"
		},
		{
			"background": "5a9ee1",
			"token": "meta.separator.diff"
		},
		{
			"background": "5a9ee1",
			"token": "meta.diff.index"
		},
		{
			"background": "5a9ee1",
			"token": "meta.diff.range"
		}
	],
	"colors": {
		"editor.foreground": "#E6E1DC",
		"editor.background": "#1C1C1C",
		"editor.selectionBackground": "#494949",
		"editor.lineHighlightBackground": "#333435",
		"editorCursor.foreground": "#FFFFFF",
		"editorWhitespace.foreground": "#404040"
	}
}

// Katzenmilch (light)
const Katzenmilch = {
	"base": "vs",
	"inherit": true,
	"rules": [
		{
			"foreground": "940494",
			"background": "444494",
			"token": "punctuation.definition.list"
		},
		{
			"foreground": "404f50",
			"background": "5f0fff",
			"fontStyle": "italic",
			"token": "comment"
		},
		{
			"foreground": "5a5f9b",
			"background": "aaafdb",
			"token": "string"
		},
		{
			"foreground": "4f827b",
			"background": "77c2bb",
			"token": "constant.numeric"
		},
		{
			"foreground": "025f69",
			"background": "7f2299",
			"token": "constant.character"
		},
		{
			"foreground": "025f69",
			"background": "7f2299",
			"token": "constant.other"
		},
		{
			"foreground": "7d7e52",
			"background": "bdbe82",
			"token": "constant.language"
		},
		{
			"foreground": "7b5d8f",
			"background": "9b9ffd",
			"fontStyle": "bold",
			"token": "storage.modifier"
		},
		{
			"foreground": "7b5cbf",
			"background": "8b5ddf",
			"fontStyle": "bold",
			"token": "storage"
		},
		{
			"foreground": "025f49",
			"background": "22ff49",
			"token": "entity.name.function"
		},
		{
			"foreground": "9d7e62",
			"background": "bdbe82",
			"token": "support.function"
		},
		{
			"foreground": "939469",
			"background": "e3e4a9",
			"token": "entity.name.function.misc"
		},
		{
			"foreground": "856f63",
			"background": "a5df93",
			"token": "entity.name.function.predicate"
		},
		{
			"foreground": "af938c",
			"background": "dfb3ac",
			"token": "entity.name.function.io"
		},
		{
			"foreground": "7bafad",
			"background": "bbdfdd",
			"token": "variable.other.external-symbol"
		},
		{
			"foreground": "316fcf",
			"background": "3aafff",
			"token": "variable.language"
		},
		{
			"foreground": "316fcf",
			"background": "3aafff",
			"token": "variable.other"
		},
		{
			"foreground": "33969f",
			"background": "05d6f9",
			"fontStyle": "italic",
			"token": "variable.parameter"
		},
		{
			"foreground": "674aa8",
			"background": "a3aad8",
			"token": "keyword"
		},
		{
			"foreground": "b9986f",
			"background": "b998df",
			"fontStyle": "bold",
			"token": "entity.name.class"
		},
		{
			"foreground": "22af9d",
			"background": "b998df",
			"token": "entity.name.structure"
		},
		{
			"foreground": "af47a9",
			"background": "af77a9",
			"token": "entity.name.type"
		},
		{
			"foreground": "cc4357",
			"background": "ffddff",
			"token": "entity.name.class"
		},
		{
			"foreground": "cc4357",
			"background": "ffddff",
			"token": "entity.name.type.class"
		},
		{
			"foreground": "ef6aa7",
			"background": "ef6aa7",
			"token": "support.class"
		},
		{
			"foreground": "dfdfd5",
			"background": "cc1b27",
			"token": "invalid"
		},
		{
			"foreground": "13499f",
			"background": "0099ff",
			"fontStyle": "italic",
			"token": "string source"
		},
		{
			"foreground": "3976a2",
			"background": "49a6d2",
			"token": "entity.name.tag"
		},
		{
			"foreground": "4946c2",
			"background": "4986c2",
			"token": "entity.other.attribute-name"
		}
	],
	"colors": {
		"editor.foreground": "#0f0009",
		"editor.background": "#e7e4e7",
		"editor.selectionBackground": "#c99cfc",
		"editor.lineHighlightBackground": "#ffffff",
		"editorCursor.foreground": "#100011",
		"editorWhitespace.foreground": "#000000",
		"editor.selectionHighlightBorder": "#d7b7fa"
	}
}

// Monokai
const Monokai = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
		{
			"foreground": "75715e",
			"token": "comment"
		},
		{
			"foreground": "e6db74",
			"token": "string"
		},
		{
			"foreground": "ae81ff",
			"token": "constant.numeric"
		},
		{
			"foreground": "ae81ff",
			"token": "constant.language"
		},
		{
			"foreground": "ae81ff",
			"token": "constant.character"
		},
		{
			"foreground": "ae81ff",
			"token": "constant.other"
		},
		{
			"foreground": "f92672",
			"token": "keyword"
		},
		{
			"foreground": "f92672",
			"token": "storage"
		},
		{
			"foreground": "66d9ef",
			"fontStyle": "italic",
			"token": "storage.type"
		},
		{
			"foreground": "a6e22e",
			"fontStyle": "underline",
			"token": "entity.name.class"
		},
		{
			"foreground": "a6e22e",
			"fontStyle": "italic underline",
			"token": "entity.other.inherited-class"
		},
		{
			"foreground": "a6e22e",
			"token": "entity.name.function"
		},
		{
			"foreground": "fd971f",
			"fontStyle": "italic",
			"token": "variable.parameter"
		},
		{
			"foreground": "f92672",
			"token": "entity.name.tag"
		},
		{
			"foreground": "a6e22e",
			"token": "entity.other.attribute-name"
		},
		{
			"foreground": "66d9ef",
			"token": "support.function"
		},
		{
			"foreground": "66d9ef",
			"token": "support.constant"
		},
		{
			"foreground": "66d9ef",
			"fontStyle": "italic",
			"token": "support.type"
		},
		{
			"foreground": "66d9ef",
			"fontStyle": "italic",
			"token": "support.class"
		},
		{
			"foreground": "f8f8f0",
			"background": "f92672",
			"token": "invalid"
		},
		{
			"foreground": "f8f8f0",
			"background": "ae81ff",
			"token": "invalid.deprecated"
		},
		{
			"foreground": "cfcfc2",
			"token": "meta.structure.dictionary.json string.quoted.double.json"
		},
		{
			"foreground": "75715e",
			"token": "meta.diff"
		},
		{
			"foreground": "75715e",
			"token": "meta.diff.header"
		},
		{
			"foreground": "f92672",
			"token": "markup.deleted"
		},
		{
			"foreground": "a6e22e",
			"token": "markup.inserted"
		},
		{
			"foreground": "e6db74",
			"token": "markup.changed"
		},
		{
			"foreground": "ae81ff",
			"token": "constant.numeric.line-number.find-in-files - match"
		},
		{
			"foreground": "e6db74",
			"token": "entity.name.filename.find-in-files"
		}
	],
	"colors": {
		"editor.foreground": "#F8F8F2",
		"editor.background": "#272822",
		"editor.selectionBackground": "#49483E",
		"editor.lineHighlightBackground": "#3E3D32",
		"editorCursor.foreground": "#F8F8F0",
		"editorWhitespace.foreground": "#3B3A32",
		"editorIndentGuide.activeBackground": "#9D550F",
		"editor.selectionHighlightBorder": "#222218"
	}
}

// Solarized-Dark
const SolarizedDark = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
		{
			"foreground": "657b83",
			"fontStyle": "italic",
			"token": "comment"
		},
		{
			"foreground": "2aa198",
			"token": "string"
		},
		{
			"foreground": "d30102",
			"token": "string.regexp"
		},
		{
			"foreground": "d33682",
			"token": "constant.numeric"
		},
		{
			"foreground": "268bd2",
			"token": "variable.language"
		},
		{
			"foreground": "268bd2",
			"token": "variable.other"
		},
		{
			"foreground": "859900",
			"token": "keyword"
		},
		{
			"foreground": "93a1a1",
			"fontStyle": "bold",
			"token": "storage"
		},
		{
			"foreground": "cb4b16",
			"token": "entity.name.class"
		},
		{
			"foreground": "cb4b16",
			"token": "entity.name.type.class"
		},
		{
			"foreground": "268bd2",
			"token": "entity.name.function"
		},
		{
			"foreground": "859900",
			"token": "punctuation.definition.variable"
		},
		{
			"foreground": "d30102",
			"token": "punctuation.section.embedded.begin"
		},
		{
			"foreground": "d30102",
			"token": "punctuation.section.embedded.end"
		},
		{
			"foreground": "b58900",
			"token": "constant.language"
		},
		{
			"foreground": "b58900",
			"token": "meta.preprocessor"
		},
		{
			"foreground": "cb4b16",
			"token": "support.function.construct"
		},
		{
			"foreground": "cb4b16",
			"token": "keyword.other.new"
		},
		{
			"foreground": "cb4b16",
			"token": "constant.character"
		},
		{
			"foreground": "cb4b16",
			"token": "constant.other"
		},
		{
			"foreground": "6c71c4",
			"token": "entity.other.inherited-class"
		},
		{
			"foreground": "268bd2",
			"fontStyle": "bold",
			"token": "entity.name.tag"
		},
		{
			"foreground": "657b83",
			"token": "punctuation.definition.tag"
		},
		{
			"foreground": "93a1a1",
			"token": "entity.other.attribute-name"
		},
		{
			"foreground": "268bd2",
			"token": "support.function"
		},
		{
			"foreground": "d30102",
			"token": "punctuation.separator.continuation"
		},
		{
			"foreground": "859900",
			"token": "support.type"
		},
		{
			"foreground": "859900",
			"token": "support.class"
		},
		{
			"foreground": "cb4b16",
			"token": "support.type.exception"
		}
	],
	"colors": {
		"editor.foreground": "#93A1A1",
		"editor.background": "#002B36",
		"editor.selectionBackground": "#073642",
		"editor.lineHighlightBackground": "#073642",
		"editorCursor.foreground": "#D30102",
		"editorWhitespace.foreground": "#93A1A1"
	}
}