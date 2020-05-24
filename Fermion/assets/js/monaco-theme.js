/////////////////////////////////
// Themes come from here:
// ~~> https://github.com/brijeshb42/monaco-themes
/////////////////////////////////
// Note:
// I made small color changes
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

// Birds-Of-Paradise
const BirdsOfParadise = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
	  {
		"foreground": "e6e1c4",
		"background": "322323",
		"token": "source"
	  },
	  {
		"foreground": "6b4e32",
		"fontStyle": "italic",
		"token": "comment"
	  },
	  {
		"foreground": "ef5d32",
		"token": "keyword"
	  },
	  {
		"foreground": "ef5d32",
		"token": "storage"
	  },
	  {
		"foreground": "efac32",
		"token": "entity.name.function"
	  },
	  {
		"foreground": "efac32",
		"token": "keyword.other.name-of-parameter.objc"
	  },
	  {
		"foreground": "efac32",
		"fontStyle": "bold",
		"token": "entity.name"
	  },
	  {
		"foreground": "6c99bb",
		"token": "constant.numeric"
	  },
	  {
		"foreground": "7daf9c",
		"token": "variable.language"
	  },
	  {
		"foreground": "7daf9c",
		"token": "variable.other"
	  },
	  {
		"foreground": "6c99bb",
		"token": "constant"
	  },
	  {
		"foreground": "efac32",
		"token": "variable.other.constant"
	  },
	  {
		"foreground": "6c99bb",
		"token": "constant.language"
	  },
	  {
		"foreground": "d9d762",
		"token": "string"
	  },
	  {
		"foreground": "efac32",
		"token": "support.function"
	  },
	  {
		"foreground": "efac32",
		"token": "support.type"
	  },
	  {
		"foreground": "6c99bb",
		"token": "support.constant"
	  },
	  {
		"foreground": "efcb43",
		"token": "meta.tag"
	  },
	  {
		"foreground": "efcb43",
		"token": "declaration.tag"
	  },
	  {
		"foreground": "efcb43",
		"token": "entity.name.tag"
	  },
	  {
		"foreground": "efcb43",
		"token": "entity.other.attribute-name"
	  },
	  {
		"foreground": "ffffff",
		"background": "990000",
		"token": "invalid"
	  },
	  {
		"foreground": "7daf9c",
		"token": "constant.character.escaped"
	  },
	  {
		"foreground": "7daf9c",
		"token": "constant.character.escape"
	  },
	  {
		"foreground": "7daf9c",
		"token": "string source"
	  },
	  {
		"foreground": "7daf9c",
		"token": "string source.ruby"
	  },
	  {
		"foreground": "e6e1dc",
		"background": "144212",
		"token": "markup.inserted"
	  },
	  {
		"foreground": "e6e1dc",
		"background": "660000",
		"token": "markup.deleted"
	  },
	  {
		"background": "2f33ab",
		"token": "meta.diff.header"
	  },
	  {
		"background": "2f33ab",
		"token": "meta.separator.diff"
	  },
	  {
		"background": "2f33ab",
		"token": "meta.diff.index"
	  },
	  {
		"background": "2f33ab",
		"token": "meta.diff.range"
	  }
	],
	"colors": {
	  "editor.foreground": "#E6E1C4",
	  "editor.background": "#372725",
	  "editor.selectionBackground": "#16120E",
	  "editor.lineHighlightBackground": "#1F1611",
	  "editorCursor.foreground": "#E6E1C4",
	  "editorWhitespace.foreground": "#42302D"
	}
}

// Clouds
const Clouds = {
	"base": "vs",
	"inherit": true,
	"rules": [
	  {
		"foreground": "bcc8ba",
		"token": "comment"
	  },
	  {
		"foreground": "5d90cd",
		"token": "string"
	  },
	  {
		"foreground": "46a609",
		"token": "constant.numeric"
	  },
	  {
		"foreground": "39946a",
		"token": "constant.language"
	  },
	  {
		"foreground": "af956f",
		"token": "keyword"
	  },
	  {
		"foreground": "af956f",
		"token": "support.constant.property-value"
	  },
	  {
		"foreground": "af956f",
		"token": "constant.other.color"
	  },
	  {
		"foreground": "96dc5f",
		"token": "keyword.other.unit"
	  },
	  {
		"foreground": "484848",
		"token": "keyword.operator"
	  },
	  {
		"foreground": "c52727",
		"token": "storage"
	  },
	  {
		"foreground": "858585",
		"token": "entity.other.inherited-class"
	  },
	  {
		"foreground": "606060",
		"token": "entity.name.tag"
	  },
	  {
		"foreground": "bf78cc",
		"token": "constant.character.entity"
	  },
	  {
		"foreground": "bf78cc",
		"token": "support.class.js"
	  },
	  {
		"foreground": "606060",
		"token": "entity.other.attribute-name"
	  },
	  {
		"foreground": "c52727",
		"token": "meta.selector.css"
	  },
	  {
		"foreground": "c52727",
		"token": "entity.name.tag.css"
	  },
	  {
		"foreground": "c52727",
		"token": "entity.other.attribute-name.id.css"
	  },
	  {
		"foreground": "c52727",
		"token": "entity.other.attribute-name.class.css"
	  },
	  {
		"foreground": "484848",
		"token": "meta.property-name.css"
	  },
	  {
		"foreground": "c52727",
		"token": "support.function"
	  },
	  {
		"background": "ff002a",
		"token": "invalid"
	  },
	  {
		"foreground": "c52727",
		"token": "punctuation.section.embedded"
	  },
	  {
		"foreground": "606060",
		"token": "punctuation.definition.tag"
	  },
	  {
		"foreground": "bf78cc",
		"token": "constant.other.color.rgb-value.css"
	  },
	  {
		"foreground": "bf78cc",
		"token": "support.constant.property-value.css"
	  }
	],
	"colors": {
	  "editor.foreground": "#000000",
	  "editor.background": "#FFFFFF",
	  "editor.selectionBackground": "#BDD5FC",
	  "editor.lineHighlightBackground": "#FFFBD1",
	  "editorCursor.foreground": "#000000",
	  "editorWhitespace.foreground": "#BFBFBF"
	}
}

// Kuroir
const Kuroir = {
	"base": "vs",
	"inherit": true,
	"rules": [
	  {
		"foreground": "949494e8",
		"background": "dcdcdc8f",
		"token": "comment"
	  },
	  {
		"foreground": "a54776",
		"background": "e9d6dc85",
		"token": "comment.line.region"
	  },
	  {
		"foreground": "668d68",
		"background": "e9e4be",
		"token": "comment.line.marker.php"
	  },
	  {
		"foreground": "456e48",
		"background": "d9eab8",
		"token": "comment.line.todo.php"
	  },
	  {
		"foreground": "880006",
		"background": "e1d0ca",
		"token": "comment.line.fixme.php"
	  },
	  {
		"foreground": "cd6839",
		"token": "constant"
	  },
	  {
		"foreground": "8b4726",
		"background": "e8e9e8",
		"token": "entity"
	  },
	  {
		"foreground": "a52a2a",
		"token": "storage"
	  },
	  {
		"foreground": "cd3700",
		"token": "keyword.control"
	  },
	  {
		"foreground": "b03060",
		"token": "support.function - variable"
	  },
	  {
		"foreground": "b03060",
		"token": "keyword.other.special-method.ruby"
	  },
	  {
		"foreground": "b83126",
		"token": "keyword.operator.comparison"
	  },
	  {
		"foreground": "b83126",
		"token": "keyword.operator.logical"
	  },
	  {
		"foreground": "639300",
		"token": "string"
	  },
	  {
		"foreground": "007e69",
		"token": "string.quoted.double.ruby source.ruby.embedded.source"
	  },
	  {
		"foreground": "104e8b",
		"token": "support"
	  },
	  {
		"foreground": "009acd",
		"token": "variable"
	  },
	  {
		"foreground": "fd1732",
		"background": "e8e9e8",
		"fontStyle": "italic underline",
		"token": "invalid.deprecated"
	  },
	  {
		"foreground": "fd1224",
		"background": "ff060026",
		"token": "invalid.illegal"
	  },
	  {
		"foreground": "7b211a",
		"background": "77ade900",
		"token": "text source"
	  },
	  {
		"foreground": "005273",
		"fontStyle": "italic",
		"token": "entity.other.inherited-class"
	  },
	  {
		"foreground": "417e00",
		"background": "c9d4be",
		"token": "string.regexp"
	  },
	  {
		"foreground": "005273",
		"token": "support.function"
	  },
	  {
		"foreground": "cf6a4c",
		"token": "support.constant"
	  },
	  {
		"fontStyle": "underline",
		"token": "entity.name.type"
	  },
	  {
		"foreground": "676767",
		"fontStyle": "italic",
		"token": "meta.cast"
	  },
	  {
		"foreground": "494949",
		"token": "meta.sgml.html meta.doctype"
	  },
	  {
		"foreground": "494949",
		"token": "meta.sgml.html meta.doctype entity"
	  },
	  {
		"foreground": "494949",
		"token": "meta.sgml.html meta.doctype string"
	  },
	  {
		"foreground": "494949",
		"token": "meta.xml-processing"
	  },
	  {
		"foreground": "494949",
		"token": "meta.xml-processing entity"
	  },
	  {
		"foreground": "494949",
		"token": "meta.xml-processing string"
	  },
	  {
		"foreground": "005273",
		"token": "meta.tag"
	  },
	  {
		"foreground": "005273",
		"token": "meta.tag entity"
	  },
	  {
		"foreground": "005273",
		"token": "source entity.name.tag"
	  },
	  {
		"foreground": "005273",
		"token": "source entity.other.attribute-name"
	  },
	  {
		"foreground": "005273",
		"token": "meta.tag.inline"
	  },
	  {
		"foreground": "005273",
		"token": "meta.tag.inline entity"
	  },
	  {
		"foreground": "b85423",
		"token": "entity.name.tag.namespace"
	  },
	  {
		"foreground": "b85423",
		"token": "entity.other.attribute-name.namespace"
	  },
	  {
		"foreground": "b83126",
		"token": "entity.name.tag.css"
	  },
	  {
		"foreground": "b12e25",
		"token": "meta.selector.css entity.other.attribute-name.tag.pseudo-class"
	  },
	  {
		"foreground": "b8002d",
		"token": "meta.selector.css entity.other.attribute-name.id"
	  },
	  {
		"foreground": "b8002d",
		"token": "entity.other.attribute-name.id.css"
	  },
	  {
		"foreground": "b8012d",
		"token": "meta.selector.css entity.other.attribute-name.class"
	  },
	  {
		"foreground": "b8012d",
		"token": "entity.other.attribute-name.class.css"
	  },
	  {
		"foreground": "005273",
		"token": "support.type.property-name.css"
	  },
	  {
		"foreground": "005273",
		"token": "meta.property-name"
	  },
	  {
		"foreground": "8693a5",
		"token": "meta.preprocessor.at-rule keyword.control.at-rule"
	  },
	  {
		"foreground": "417e00",
		"token": "meta.property-value"
	  },
	  {
		"foreground": "b8860b",
		"token": "constant.other.color"
	  },
	  {
		"foreground": "ee3a8c",
		"token": "keyword.other.important"
	  },
	  {
		"foreground": "ee3a8c",
		"token": "keyword.other.default"
	  },
	  {
		"foreground": "417e00",
		"token": "meta.property-value support.constant.named-color.css"
	  },
	  {
		"foreground": "417e00",
		"token": "meta.property-value constant"
	  },
	  {
		"foreground": "417e00",
		"token": "meta.constructor.argument.css"
	  },
	  {
		"foreground": "9a5925",
		"token": "constant.numeric"
	  },
	  {
		"foreground": "9f5e3d",
		"token": "keyword.other"
	  },
	  {
		"foreground": "1b76b0",
		"token": "source.scss support.function.misc"
	  },
	  {
		"foreground": "f8bebe",
		"background": "82000e",
		"fontStyle": "italic",
		"token": "meta.diff"
	  },
	  {
		"foreground": "f8bebe",
		"background": "82000e",
		"fontStyle": "italic",
		"token": "meta.diff.header"
	  },
	  {
		"foreground": "f8f8f8",
		"background": "420e09",
		"token": "markup.deleted"
	  },
	  {
		"foreground": "f8f8f8",
		"background": "4a410d",
		"token": "markup.changed"
	  },
	  {
		"foreground": "f8f8f8",
		"background": "253b22",
		"token": "markup.inserted"
	  },
	  {
		"foreground": "cd2626",
		"fontStyle": "italic",
		"token": "markup.italic"
	  },
	  {
		"foreground": "8b1a1a",
		"fontStyle": "bold",
		"token": "markup.bold"
	  },
	  {
		"foreground": "e18964",
		"fontStyle": "underline",
		"token": "markup.underline"
	  },
	  {
		"foreground": "8b7765",
		"background": "fee09c12",
		"fontStyle": "italic",
		"token": "markup.quote"
	  },
	  {
		"foreground": "b8012d",
		"background": "bf61330d",
		"token": "markup.heading"
	  },
	  {
		"foreground": "b8012d",
		"background": "bf61330d",
		"token": "markup.heading entity"
	  },
	  {
		"foreground": "8f5b26",
		"token": "markup.list"
	  },
	  {
		"foreground": "578bb3",
		"background": "b1b3ba08",
		"token": "markup.raw"
	  },
	  {
		"foreground": "f67b37",
		"fontStyle": "italic",
		"token": "markup comment"
	  },
	  {
		"foreground": "60a633",
		"background": "242424",
		"token": "meta.separator"
	  },
	  {
		"foreground": "578bb3",
		"background": "b1b3ba08",
		"token": "markup.other"
	  },
	  {
		"background": "eeeeee29",
		"token": "meta.line.entry.logfile"
	  },
	  {
		"background": "eeeeee29",
		"token": "meta.line.exit.logfile"
	  },
	  {
		"background": "751012",
		"token": "meta.line.error.logfile"
	  },
	  {
		"background": "dcdcdc8f",
		"token": "punctuation.definition.end"
	  },
	  {
		"foreground": "629f9e",
		"token": "entity.other.attribute-name.html"
	  },
	  {
		"foreground": "79a316",
		"token": "string.quoted.double.js"
	  },
	  {
		"foreground": "79a316",
		"token": "string.quoted.single.js"
	  },
	  {
		"foreground": "488c45",
		"fontStyle": "italic",
		"token": "entity.name.function.js"
	  },
	  {
		"foreground": "666666",
		"token": "source.js.embedded.html"
	  },
	  {
		"foreground": "bb3182",
		"token": "storage.type.js"
	  },
	  {
		"foreground": "338fd5",
		"token": "support.class.js"
	  },
	  {
		"foreground": "a99904",
		"fontStyle": "italic",
		"token": "keyword.control.js"
	  },
	  {
		"foreground": "a99904",
		"fontStyle": "italic",
		"token": "keyword.operator.js"
	  },
	  {
		"foreground": "616838",
		"background": "d7d7a7",
		"token": "entity.name.class"
	  },
	  {
		"background": "968f96",
		"token": "active_guide"
	  },
	  {
		"background": "cbdc2f38",
		"token": "highlight_matching_word"
	  }
	],
	"colors": {
	  "editor.foreground": "#363636",
	  "editor.background": "#E8E9E8",
	  "editor.selectionBackground": "#F5AA0091",
	  "editor.lineHighlightBackground": "#CBDC2F38",
	  "editorCursor.foreground": "#202020",
	  "editorWhitespace.foreground": "#0000004A",
	  "editorIndentGuide.background": "#8F8F8F",
	  "editorIndentGuide.activeBackground": "#FA2828"
	}
}

// NightOwl
const NightOwl = {
	"base": "vs-dark",
	"inherit": true,
	"rules": [
	  {
		"foreground": "637777",
		"token": "comment"
	  },
	  {
		"foreground": "addb67",
		"token": "string"
	  },
	  {
		"foreground": "ecc48d",
		"token": "vstring.quoted"
	  },
	  {
		"foreground": "ecc48d",
		"token": "variable.other.readwrite.js"
	  },
	  {
		"foreground": "5ca7e4",
		"token": "string.regexp"
	  },
	  {
		"foreground": "5ca7e4",
		"token": "string.regexp keyword.other"
	  },
	  {
		"foreground": "5f7e97",
		"token": "meta.function punctuation.separator.comma"
	  },
	  {
		"foreground": "f78c6c",
		"token": "constant.numeric"
	  },
	  {
		"foreground": "f78c6c",
		"token": "constant.character.numeric"
	  },
	  {
		"foreground": "addb67",
		"token": "variable"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword"
	  },
	  {
		"foreground": "c792ea",
		"token": "punctuation.accessor"
	  },
	  {
		"foreground": "c792ea",
		"token": "storage"
	  },
	  {
		"foreground": "c792ea",
		"token": "meta.var.expr"
	  },
	  {
		"foreground": "c792ea",
		"token": "meta.class meta.method.declaration meta.var.expr storage.type.jsm"
	  },
	  {
		"foreground": "c792ea",
		"token": "storage.type.property.js"
	  },
	  {
		"foreground": "c792ea",
		"token": "storage.type.property.ts"
	  },
	  {
		"foreground": "c792ea",
		"token": "storage.type.property.tsx"
	  },
	  {
		"foreground": "82aaff",
		"token": "storage.type"
	  },
	  {
		"foreground": "ffcb8b",
		"token": "entity.name.class"
	  },
	  {
		"foreground": "ffcb8b",
		"token": "meta.class entity.name.type.class"
	  },
	  {
		"foreground": "addb67",
		"token": "entity.other.inherited-class"
	  },
	  {
		"foreground": "82aaff",
		"token": "entity.name.function"
	  },
	  {
		"foreground": "addb67",
		"token": "punctuation.definition.variable"
	  },
	  {
		"foreground": "d3423e",
		"token": "punctuation.section.embedded"
	  },
	  {
		"foreground": "d6deeb",
		"token": "punctuation.terminator.expression"
	  },
	  {
		"foreground": "d6deeb",
		"token": "punctuation.definition.arguments"
	  },
	  {
		"foreground": "d6deeb",
		"token": "punctuation.definition.array"
	  },
	  {
		"foreground": "d6deeb",
		"token": "punctuation.section.array"
	  },
	  {
		"foreground": "d6deeb",
		"token": "meta.array"
	  },
	  {
		"foreground": "d9f5dd",
		"token": "punctuation.definition.list.begin"
	  },
	  {
		"foreground": "d9f5dd",
		"token": "punctuation.definition.list.end"
	  },
	  {
		"foreground": "d9f5dd",
		"token": "punctuation.separator.arguments"
	  },
	  {
		"foreground": "d9f5dd",
		"token": "punctuation.definition.list"
	  },
	  {
		"foreground": "d3423e",
		"token": "string.template meta.template.expression"
	  },
	  {
		"foreground": "d6deeb",
		"token": "string.template punctuation.definition.string"
	  },
	  {
		"foreground": "c792ea",
		"fontStyle": "italic",
		"token": "italic"
	  },
	  {
		"foreground": "addb67",
		"fontStyle": "bold",
		"token": "bold"
	  },
	  {
		"foreground": "82aaff",
		"token": "constant.language"
	  },
	  {
		"foreground": "82aaff",
		"token": "punctuation.definition.constant"
	  },
	  {
		"foreground": "82aaff",
		"token": "variable.other.constant"
	  },
	  {
		"foreground": "7fdbca",
		"token": "support.function.construct"
	  },
	  {
		"foreground": "7fdbca",
		"token": "keyword.other.new"
	  },
	  {
		"foreground": "82aaff",
		"token": "constant.character"
	  },
	  {
		"foreground": "82aaff",
		"token": "constant.other"
	  },
	  {
		"foreground": "f78c6c",
		"token": "constant.character.escape"
	  },
	  {
		"foreground": "addb67",
		"token": "entity.other.inherited-class"
	  },
	  {
		"foreground": "d7dbe0",
		"token": "variable.parameter"
	  },
	  {
		"foreground": "7fdbca",
		"token": "entity.name.tag"
	  },
	  {
		"foreground": "cc2996",
		"token": "punctuation.definition.tag.html"
	  },
	  {
		"foreground": "cc2996",
		"token": "punctuation.definition.tag.begin"
	  },
	  {
		"foreground": "cc2996",
		"token": "punctuation.definition.tag.end"
	  },
	  {
		"foreground": "addb67",
		"token": "entity.other.attribute-name"
	  },
	  {
		"foreground": "addb67",
		"token": "entity.name.tag.custom"
	  },
	  {
		"foreground": "82aaff",
		"token": "support.function"
	  },
	  {
		"foreground": "82aaff",
		"token": "support.constant"
	  },
	  {
		"foreground": "7fdbca",
		"token": "upport.constant.meta.property-value"
	  },
	  {
		"foreground": "addb67",
		"token": "support.type"
	  },
	  {
		"foreground": "addb67",
		"token": "support.class"
	  },
	  {
		"foreground": "addb67",
		"token": "support.variable.dom"
	  },
	  {
		"foreground": "7fdbca",
		"token": "support.constant"
	  },
	  {
		"foreground": "7fdbca",
		"token": "keyword.other.special-method"
	  },
	  {
		"foreground": "7fdbca",
		"token": "keyword.other.new"
	  },
	  {
		"foreground": "7fdbca",
		"token": "keyword.other.debugger"
	  },
	  {
		"foreground": "7fdbca",
		"token": "keyword.control"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.comparison"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.flow.js"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.flow.ts"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.flow.tsx"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.ruby"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.module.ruby"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.class.ruby"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.def.ruby"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.loop.js"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.loop.ts"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.import.js"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.import.ts"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.import.tsx"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.from.js"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.from.ts"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.control.from.tsx"
	  },
	  {
		"foreground": "ffffff",
		"background": "ff2c83",
		"token": "invalid"
	  },
	  {
		"foreground": "ffffff",
		"background": "d3423e",
		"token": "invalid.deprecated"
	  },
	  {
		"foreground": "7fdbca",
		"token": "keyword.operator"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.relational"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.assignement"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.arithmetic"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.bitwise"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.increment"
	  },
	  {
		"foreground": "c792ea",
		"token": "keyword.operator.ternary"
	  },
	  {
		"foreground": "637777",
		"token": "comment.line.double-slash"
	  },
	  {
		"foreground": "cdebf7",
		"token": "object"
	  },
	  {
		"foreground": "ff5874",
		"token": "constant.language.null"
	  },
	  {
		"foreground": "d6deeb",
		"token": "meta.brace"
	  },
	  {
		"foreground": "c792ea",
		"token": "meta.delimiter.period"
	  },
	  {
		"foreground": "d9f5dd",
		"token": "punctuation.definition.string"
	  },
	  {
		"foreground": "ff5874",
		"token": "constant.language.boolean"
	  },
	  {
		"foreground": "ffffff",
		"token": "object.comma"
	  },
	  {
		"foreground": "7fdbca",
		"token": "variable.parameter.function"
	  },
	  {
		"foreground": "80cbc4",
		"token": "support.type.vendor.property-name"
	  },
	  {
		"foreground": "80cbc4",
		"token": "support.constant.vendor.property-value"
	  },
	  {
		"foreground": "80cbc4",
		"token": "support.type.property-name"
	  },
	  {
		"foreground": "80cbc4",
		"token": "meta.property-list entity.name.tag"
	  },
	  {
		"foreground": "57eaf1",
		"token": "meta.property-list entity.name.tag.reference"
	  },
	  {
		"foreground": "f78c6c",
		"token": "constant.other.color.rgb-value punctuation.definition.constant"
	  },
	  {
		"foreground": "ffeb95",
		"token": "constant.other.color"
	  },
	  {
		"foreground": "ffeb95",
		"token": "keyword.other.unit"
	  },
	  {
		"foreground": "c792ea",
		"token": "meta.selector"
	  },
	  {
		"foreground": "fad430",
		"token": "entity.other.attribute-name.id"
	  },
	  {
		"foreground": "80cbc4",
		"token": "meta.property-name"
	  },
	  {
		"foreground": "c792ea",
		"token": "entity.name.tag.doctype"
	  },
	  {
		"foreground": "c792ea",
		"token": "meta.tag.sgml.doctype"
	  },
	  {
		"foreground": "d9f5dd",
		"token": "punctuation.definition.parameters"
	  },
	  {
		"foreground": "ecc48d",
		"token": "string.quoted"
	  },
	  {
		"foreground": "ecc48d",
		"token": "string.quoted.double"
	  },
	  {
		"foreground": "ecc48d",
		"token": "string.quoted.single"
	  },
	  {
		"foreground": "addb67",
		"token": "support.constant.math"
	  },
	  {
		"foreground": "addb67",
		"token": "support.type.property-name.json"
	  },
	  {
		"foreground": "addb67",
		"token": "support.constant.json"
	  },
	  {
		"foreground": "c789d6",
		"token": "meta.structure.dictionary.value.json string.quoted.double"
	  },
	  {
		"foreground": "80cbc4",
		"token": "string.quoted.double.json punctuation.definition.string.json"
	  },
	  {
		"foreground": "ff5874",
		"token": "meta.structure.dictionary.json meta.structure.dictionary.value constant.language"
	  },
	  {
		"foreground": "d6deeb",
		"token": "variable.other.ruby"
	  },
	  {
		"foreground": "ecc48d",
		"token": "entity.name.type.class.ruby"
	  },
	  {
		"foreground": "ecc48d",
		"token": "keyword.control.class.ruby"
	  },
	  {
		"foreground": "ecc48d",
		"token": "meta.class.ruby"
	  },
	  {
		"foreground": "7fdbca",
		"token": "constant.language.symbol.hashkey.ruby"
	  },
	  {
		"foreground": "e0eddd",
		"background": "a57706",
		"fontStyle": "italic",
		"token": "meta.diff"
	  },
	  {
		"foreground": "e0eddd",
		"background": "a57706",
		"fontStyle": "italic",
		"token": "meta.diff.header"
	  },
	  {
		"foreground": "ef535090",
		"fontStyle": "italic",
		"token": "markup.deleted"
	  },
	  {
		"foreground": "a2bffc",
		"fontStyle": "italic",
		"token": "markup.changed"
	  },
	  {
		"foreground": "a2bffc",
		"fontStyle": "italic",
		"token": "meta.diff.header.git"
	  },
	  {
		"foreground": "a2bffc",
		"fontStyle": "italic",
		"token": "meta.diff.header.from-file"
	  },
	  {
		"foreground": "a2bffc",
		"fontStyle": "italic",
		"token": "meta.diff.header.to-file"
	  },
	  {
		"foreground": "219186",
		"background": "eae3ca",
		"token": "markup.inserted"
	  },
	  {
		"foreground": "d3201f",
		"token": "other.package.exclude"
	  },
	  {
		"foreground": "d3201f",
		"token": "other.remove"
	  },
	  {
		"foreground": "269186",
		"token": "other.add"
	  },
	  {
		"foreground": "ff5874",
		"token": "constant.language.python"
	  },
	  {
		"foreground": "82aaff",
		"token": "variable.parameter.function.python"
	  },
	  {
		"foreground": "82aaff",
		"token": "meta.function-call.arguments.python"
	  },
	  {
		"foreground": "b2ccd6",
		"token": "meta.function-call.python"
	  },
	  {
		"foreground": "b2ccd6",
		"token": "meta.function-call.generic.python"
	  },
	  {
		"foreground": "d6deeb",
		"token": "punctuation.python"
	  },
	  {
		"foreground": "addb67",
		"token": "entity.name.function.decorator.python"
	  },
	  {
		"foreground": "8eace3",
		"token": "source.python variable.language.special"
	  },
	  {
		"foreground": "82b1ff",
		"token": "markup.heading.markdown"
	  },
	  {
		"foreground": "c792ea",
		"fontStyle": "italic",
		"token": "markup.italic.markdown"
	  },
	  {
		"foreground": "addb67",
		"fontStyle": "bold",
		"token": "markup.bold.markdown"
	  },
	  {
		"foreground": "697098",
		"token": "markup.quote.markdown"
	  },
	  {
		"foreground": "80cbc4",
		"token": "markup.inline.raw.markdown"
	  },
	  {
		"foreground": "ff869a",
		"token": "markup.underline.link.markdown"
	  },
	  {
		"foreground": "ff869a",
		"token": "markup.underline.link.image.markdown"
	  },
	  {
		"foreground": "d6deeb",
		"token": "string.other.link.title.markdown"
	  },
	  {
		"foreground": "d6deeb",
		"token": "string.other.link.description.markdown"
	  },
	  {
		"foreground": "82b1ff",
		"token": "punctuation.definition.string.markdown"
	  },
	  {
		"foreground": "82b1ff",
		"token": "punctuation.definition.string.begin.markdown"
	  },
	  {
		"foreground": "82b1ff",
		"token": "punctuation.definition.string.end.markdown"
	  },
	  {
		"foreground": "82b1ff",
		"token": "meta.link.inline.markdown punctuation.definition.string"
	  },
	  {
		"foreground": "7fdbca",
		"token": "punctuation.definition.metadata.markdown"
	  },
	  {
		"foreground": "82b1ff",
		"token": "beginning.punctuation.definition.list.markdown"
	  }
	],
	"colors": {
	  "editor.foreground": "#d6deeb",
	  "editor.background": "#011627",
	  "editor.selectionBackground": "#5f7e9779",
	  "editor.lineHighlightBackground": "#010E17",
	  "editorCursor.foreground": "#80a4c2",
	  "editorWhitespace.foreground": "#2e2040",
	  "editorIndentGuide.background": "#5e81ce52",
	  "editor.selectionHighlightBorder": "#122d42"
	}
}

// Solarized-Light
const SolarizedLight = {
	"base": "vs",
	"inherit": true,
	"rules": [
	  {
		"foreground": "93a1a1",
		"token": "comment"
	  },
	  {
		"foreground": "2aa198",
		"token": "string"
	  },
	  {
		"foreground": "586e75",
		"token": "string"
	  },
	  {
		"foreground": "dc322f",
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
		"foreground": "073642",
		"fontStyle": "bold",
		"token": "storage"
	  },
	  {
		"foreground": "268bd2",
		"token": "entity.name.class"
	  },
	  {
		"foreground": "268bd2",
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
		"foreground": "dc322f",
		"token": "punctuation.section.embedded.begin"
	  },
	  {
		"foreground": "dc322f",
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
		"foreground": "dc322f",
		"token": "support.function.construct"
	  },
	  {
		"foreground": "dc322f",
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
		"foreground": "268bd2",
		"fontStyle": "bold",
		"token": "entity.name.tag"
	  },
	  {
		"foreground": "93a1a1",
		"token": "punctuation.definition.tag.html"
	  },
	  {
		"foreground": "93a1a1",
		"token": "punctuation.definition.tag.begin"
	  },
	  {
		"foreground": "93a1a1",
		"token": "punctuation.definition.tag.end"
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
		"foreground": "dc322f",
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
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.other.special-method"
	  },
	  {
		"foreground": "2aa198",
		"token": "string.quoted.double"
	  },
	  {
		"foreground": "2aa198",
		"token": "string.quoted.single"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.begin"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.end"
	  },
	  {
		"foreground": "b58900",
		"token": "entity.name.tag.css"
	  },
	  {
		"foreground": "b58900",
		"token": "support.type.property-name.css"
	  },
	  {
		"foreground": "b58900",
		"token": "meta.property-name.css"
	  },
	  {
		"foreground": "dc322f",
		"token": "source.css"
	  },
	  {
		"foreground": "586e75",
		"token": "meta.selector.css"
	  },
	  {
		"foreground": "6c71c4",
		"token": "punctuation.section.property-list.css"
	  },
	  {
		"foreground": "2aa198",
		"token": "meta.property-value.css constant.numeric.css"
	  },
	  {
		"foreground": "2aa198",
		"token": "keyword.other.unit.css"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.other.color.rgb-value.css"
	  },
	  {
		"foreground": "2aa198",
		"token": "meta.property-value.css"
	  },
	  {
		"foreground": "dc322f",
		"token": "keyword.other.important.css"
	  },
	  {
		"foreground": "2aa198",
		"token": "support.constant.color"
	  },
	  {
		"foreground": "859900",
		"token": "entity.name.tag.css"
	  },
	  {
		"foreground": "586e75",
		"token": "punctuation.separator.key-value.css"
	  },
	  {
		"foreground": "586e75",
		"token": "punctuation.terminator.rule.css"
	  },
	  {
		"foreground": "268bd2",
		"token": "entity.other.attribute-name.class.css"
	  },
	  {
		"foreground": "cb4b16",
		"token": "entity.other.attribute-name.pseudo-element.css"
	  },
	  {
		"foreground": "cb4b16",
		"token": "entity.other.attribute-name.pseudo-class.css"
	  },
	  {
		"foreground": "268bd2",
		"token": "entity.other.attribute-name.id.css"
	  },
	  {
		"foreground": "b58900",
		"token": "meta.function.js"
	  },
	  {
		"foreground": "b58900",
		"token": "entity.name.function.js"
	  },
	  {
		"foreground": "b58900",
		"token": "support.function.dom.js"
	  },
	  {
		"foreground": "b58900",
		"token": "text.html.basic source.js.embedded.html"
	  },
	  {
		"foreground": "268bd2",
		"token": "storage.type.function.js"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.numeric.js"
	  },
	  {
		"foreground": "268bd2",
		"token": "meta.brace.square.js"
	  },
	  {
		"foreground": "268bd2",
		"token": "storage.type.js"
	  },
	  {
		"foreground": "93a1a1",
		"token": "meta.brace.round"
	  },
	  {
		"foreground": "93a1a1",
		"token": "punctuation.definition.parameters.begin.js"
	  },
	  {
		"foreground": "93a1a1",
		"token": "punctuation.definition.parameters.end.js"
	  },
	  {
		"foreground": "268bd2",
		"token": "meta.brace.curly.js"
	  },
	  {
		"foreground": "93a1a1",
		"fontStyle": "italic",
		"token": "entity.name.tag.doctype.html"
	  },
	  {
		"foreground": "93a1a1",
		"fontStyle": "italic",
		"token": "meta.tag.sgml.html"
	  },
	  {
		"foreground": "93a1a1",
		"fontStyle": "italic",
		"token": "string.quoted.double.doctype.identifiers-and-DTDs.html"
	  },
	  {
		"foreground": "839496",
		"fontStyle": "italic",
		"token": "comment.block.html"
	  },
	  {
		"fontStyle": "italic",
		"token": "entity.name.tag.script.html"
	  },
	  {
		"foreground": "2aa198",
		"token": "source.css.embedded.html string.quoted.double.html"
	  },
	  {
		"foreground": "cb4b16",
		"fontStyle": "bold",
		"token": "text.html.ruby"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic meta.tag.other.html"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic meta.tag.any.html"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic meta.tag.block.any"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic meta.tag.inline.any"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic meta.tag.structure.any.html"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic source.js.embedded.html"
	  },
	  {
		"foreground": "657b83",
		"token": "punctuation.separator.key-value.html"
	  },
	  {
		"foreground": "657b83",
		"token": "text.html.basic entity.other.attribute-name.html"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.html.basic meta.tag.structure.any.html punctuation.definition.string.begin.html"
	  },
	  {
		"foreground": "2aa198",
		"token": "punctuation.definition.string.begin.html"
	  },
	  {
		"foreground": "2aa198",
		"token": "punctuation.definition.string.end.html"
	  },
	  {
		"foreground": "268bd2",
		"fontStyle": "bold",
		"token": "entity.name.tag.block.any.html"
	  },
	  {
		"fontStyle": "italic",
		"token": "source.css.embedded.html entity.name.tag.style.html"
	  },
	  {
		"foreground": "839496",
		"fontStyle": "italic",
		"token": "source.css.embedded.html"
	  },
	  {
		"foreground": "839496",
		"fontStyle": "italic",
		"token": "comment.block.html"
	  },
	  {
		"foreground": "268bd2",
		"token": "punctuation.definition.variable.ruby"
	  },
	  {
		"foreground": "657b83",
		"token": "meta.function.method.with-arguments.ruby"
	  },
	  {
		"foreground": "2aa198",
		"token": "variable.language.ruby"
	  },
	  {
		"foreground": "268bd2",
		"token": "entity.name.function.ruby"
	  },
	  {
		"foreground": "859900",
		"fontStyle": "bold",
		"token": "keyword.control.ruby"
	  },
	  {
		"foreground": "859900",
		"fontStyle": "bold",
		"token": "keyword.control.def.ruby"
	  },
	  {
		"foreground": "859900",
		"token": "keyword.control.class.ruby"
	  },
	  {
		"foreground": "859900",
		"token": "meta.class.ruby"
	  },
	  {
		"foreground": "b58900",
		"token": "entity.name.type.class.ruby"
	  },
	  {
		"foreground": "859900",
		"token": "keyword.control.ruby"
	  },
	  {
		"foreground": "b58900",
		"token": "support.class.ruby"
	  },
	  {
		"foreground": "859900",
		"token": "keyword.other.special-method.ruby"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.language.ruby"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.numeric.ruby"
	  },
	  {
		"foreground": "b58900",
		"token": "variable.other.constant.ruby"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.other.symbol.ruby"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.section.embedded.ruby"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.begin.ruby"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.end.ruby"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.other.special-method.ruby"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.control.import.include.php"
	  },
	  {
		"foreground": "839496",
		"token": "text.html.ruby meta.tag.inline.any.html"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.html.ruby punctuation.definition.string.begin"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.html.ruby punctuation.definition.string.end"
	  },
	  {
		"foreground": "839496",
		"token": "punctuation.definition.string.begin"
	  },
	  {
		"foreground": "839496",
		"token": "punctuation.definition.string.end"
	  },
	  {
		"foreground": "dc322f",
		"token": "keyword.operator.index-start.php"
	  },
	  {
		"foreground": "dc322f",
		"token": "keyword.operator.index-end.php"
	  },
	  {
		"foreground": "586e75",
		"token": "meta.array.php"
	  },
	  {
		"foreground": "b58900",
		"token": "meta.array.php support.function.construct.php"
	  },
	  {
		"foreground": "b58900",
		"token": "meta.array.empty.php support.function.construct.php"
	  },
	  {
		"foreground": "b58900",
		"token": "support.function.construct.php"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.array.begin"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.array.end"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.numeric.php"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.other.new.php"
	  },
	  {
		"foreground": "586e75",
		"token": "support.class.php"
	  },
	  {
		"foreground": "586e75",
		"token": "keyword.operator.class"
	  },
	  {
		"foreground": "93a1a1",
		"token": "variable.other.property.php"
	  },
	  {
		"foreground": "b58900",
		"token": "storage.modifier.extends.php"
	  },
	  {
		"foreground": "b58900",
		"token": "storage.type.class.php"
	  },
	  {
		"foreground": "b58900",
		"token": "keyword.operator.class.php"
	  },
	  {
		"foreground": "586e75",
		"token": "meta.other.inherited-class.php"
	  },
	  {
		"foreground": "859900",
		"token": "storage.type.php"
	  },
	  {
		"foreground": "93a1a1",
		"token": "entity.name.function.php"
	  },
	  {
		"foreground": "859900",
		"token": "support.function.construct.php"
	  },
	  {
		"foreground": "839496",
		"token": "entity.name.type.class.php"
	  },
	  {
		"foreground": "839496",
		"token": "meta.function-call.php"
	  },
	  {
		"foreground": "839496",
		"token": "meta.function-call.static.php"
	  },
	  {
		"foreground": "839496",
		"token": "meta.function-call.object.php"
	  },
	  {
		"foreground": "93a1a1",
		"token": "keyword.other.phpdoc"
	  },
	  {
		"foreground": "cb4b16",
		"token": "source.php.embedded.block.html"
	  },
	  {
		"foreground": "cb4b16",
		"token": "storage.type.function.php"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.numeric.c"
	  },
	  {
		"foreground": "cb4b16",
		"token": "meta.preprocessor.c.include"
	  },
	  {
		"foreground": "cb4b16",
		"token": "meta.preprocessor.macro.c"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.control.import.define.c"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.control.import.include.c"
	  },
	  {
		"foreground": "cb4b16",
		"token": "entity.name.function.preprocessor.c"
	  },
	  {
		"foreground": "2aa198",
		"token": "meta.preprocessor.c.include string.quoted.other.lt-gt.include.c"
	  },
	  {
		"foreground": "2aa198",
		"token": "meta.preprocessor.c.include punctuation.definition.string.begin.c"
	  },
	  {
		"foreground": "2aa198",
		"token": "meta.preprocessor.c.include punctuation.definition.string.end.c"
	  },
	  {
		"foreground": "586e75",
		"token": "support.function.C99.c"
	  },
	  {
		"foreground": "586e75",
		"token": "support.function.any-method.c"
	  },
	  {
		"foreground": "586e75",
		"token": "entity.name.function.c"
	  },
	  {
		"foreground": "2aa198",
		"token": "punctuation.definition.string.begin.c"
	  },
	  {
		"foreground": "2aa198",
		"token": "punctuation.definition.string.end.c"
	  },
	  {
		"foreground": "b58900",
		"token": "storage.type.c"
	  },
	  {
		"foreground": "e0eddd",
		"background": "b58900",
		"fontStyle": "italic",
		"token": "meta.diff"
	  },
	  {
		"foreground": "e0eddd",
		"background": "b58900",
		"fontStyle": "italic",
		"token": "meta.diff.header"
	  },
	  {
		"foreground": "dc322f",
		"background": "eee8d5",
		"token": "markup.deleted"
	  },
	  {
		"foreground": "cb4b16",
		"background": "eee8d5",
		"token": "markup.changed"
	  },
	  {
		"foreground": "219186",
		"background": "eee8d5",
		"token": "markup.inserted"
	  },
	  {
		"foreground": "e0eddd",
		"background": "a57706",
		"token": "text.html.markdown meta.dummy.line-break"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.html.markdown markup.raw.inline"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.restructuredtext markup.raw"
	  },
	  {
		"foreground": "dc322f",
		"token": "other.package.exclude"
	  },
	  {
		"foreground": "dc322f",
		"token": "other.remove"
	  },
	  {
		"foreground": "2aa198",
		"token": "other.add"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.section.group.tex"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.arguments.begin.latex"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.arguments.end.latex"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.arguments.latex"
	  },
	  {
		"foreground": "b58900",
		"token": "meta.group.braces.tex"
	  },
	  {
		"foreground": "b58900",
		"token": "string.other.math.tex"
	  },
	  {
		"foreground": "cb4b16",
		"token": "variable.parameter.function.latex"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.constant.math.tex"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.tex.latex constant.other.math.tex"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.other.general.math.tex"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.other.general.math.tex"
	  },
	  {
		"foreground": "2aa198",
		"token": "constant.character.math.tex"
	  },
	  {
		"foreground": "b58900",
		"token": "string.other.math.tex"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.begin.tex"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.end.tex"
	  },
	  {
		"foreground": "2aa198",
		"token": "keyword.control.label.latex"
	  },
	  {
		"foreground": "2aa198",
		"token": "text.tex.latex constant.other.general.math.tex"
	  },
	  {
		"foreground": "dc322f",
		"token": "variable.parameter.definition.label.latex"
	  },
	  {
		"foreground": "859900",
		"token": "support.function.be.latex"
	  },
	  {
		"foreground": "cb4b16",
		"token": "support.function.section.latex"
	  },
	  {
		"foreground": "2aa198",
		"token": "support.function.general.tex"
	  },
	  {
		"fontStyle": "italic",
		"token": "punctuation.definition.comment.tex"
	  },
	  {
		"fontStyle": "italic",
		"token": "comment.line.percentage.tex"
	  },
	  {
		"foreground": "2aa198",
		"token": "keyword.control.ref.latex"
	  },
	  {
		"foreground": "586e75",
		"token": "string.quoted.double.block.python"
	  },
	  {
		"foreground": "859900",
		"token": "storage.type.class.python"
	  },
	  {
		"foreground": "859900",
		"token": "storage.type.function.python"
	  },
	  {
		"foreground": "859900",
		"token": "storage.modifier.global.python"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.control.import.python"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.control.import.from.python"
	  },
	  {
		"foreground": "b58900",
		"token": "support.type.exception.python"
	  },
	  {
		"foreground": "859900",
		"token": "support.function.builtin.shell"
	  },
	  {
		"foreground": "cb4b16",
		"token": "variable.other.normal.shell"
	  },
	  {
		"foreground": "268bd2",
		"token": "source.shell"
	  },
	  {
		"foreground": "586e75",
		"token": "meta.scope.for-in-loop.shell"
	  },
	  {
		"foreground": "586e75",
		"token": "variable.other.loop.shell"
	  },
	  {
		"foreground": "859900",
		"token": "punctuation.definition.string.end.shell"
	  },
	  {
		"foreground": "859900",
		"token": "punctuation.definition.string.begin.shell"
	  },
	  {
		"foreground": "586e75",
		"token": "meta.scope.case-block.shell"
	  },
	  {
		"foreground": "586e75",
		"token": "meta.scope.case-body.shell"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.logical-expression.shell"
	  },
	  {
		"fontStyle": "italic",
		"token": "comment.line.number-sign.shell"
	  },
	  {
		"foreground": "cb4b16",
		"token": "keyword.other.import.java"
	  },
	  {
		"foreground": "586e75",
		"token": "storage.modifier.import.java"
	  },
	  {
		"foreground": "b58900",
		"token": "meta.class.java storage.modifier.java"
	  },
	  {
		"foreground": "586e75",
		"token": "source.java comment.block"
	  },
	  {
		"foreground": "586e75",
		"token": "comment.block meta.documentation.tag.param.javadoc keyword.other.documentation.param.javadoc"
	  },
	  {
		"foreground": "b58900",
		"token": "punctuation.definition.variable.perl"
	  },
	  {
		"foreground": "b58900",
		"token": "variable.other.readwrite.global.perl"
	  },
	  {
		"foreground": "b58900",
		"token": "variable.other.predefined.perl"
	  },
	  {
		"foreground": "b58900",
		"token": "keyword.operator.comparison.perl"
	  },
	  {
		"foreground": "859900",
		"token": "support.function.perl"
	  },
	  {
		"foreground": "586e75",
		"fontStyle": "italic",
		"token": "comment.line.number-sign.perl"
	  },
	  {
		"foreground": "2aa198",
		"token": "punctuation.definition.string.begin.perl"
	  },
	  {
		"foreground": "2aa198",
		"token": "punctuation.definition.string.end.perl"
	  },
	  {
		"foreground": "dc322f",
		"token": "constant.character.escape.perl"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.markdown"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.1.markdown"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.2.markdown"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.3.markdown"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.4.markdown"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.5.markdown"
	  },
	  {
		"foreground": "268bd2",
		"token": "markup.heading.6.markdown"
	  },
	  {
		"foreground": "586e75",
		"fontStyle": "bold",
		"token": "markup.bold.markdown"
	  },
	  {
		"foreground": "586e75",
		"fontStyle": "italic",
		"token": "markup.italic.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.bold.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.italic.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.raw.markdown"
	  },
	  {
		"foreground": "b58900",
		"token": "markup.list.unnumbered.markdown"
	  },
	  {
		"foreground": "859900",
		"token": "markup.list.numbered.markdown"
	  },
	  {
		"foreground": "2aa198",
		"token": "markup.raw.block.markdown"
	  },
	  {
		"foreground": "2aa198",
		"token": "markup.raw.inline.markdown"
	  },
	  {
		"foreground": "6c71c4",
		"token": "markup.quote.markdown"
	  },
	  {
		"foreground": "6c71c4",
		"token": "punctuation.definition.blockquote.markdown"
	  },
	  {
		"foreground": "d33682",
		"token": "meta.separator.markdown"
	  },
	  {
		"foreground": "839496",
		"token": "markup.underline.link.markdown"
	  },
	  {
		"foreground": "839496",
		"token": "markup.underline.link.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "meta.link.inet.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "meta.link.email.lt-gt.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.begin.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.string.end.markdown"
	  },
	  {
		"foreground": "dc322f",
		"token": "punctuation.definition.link.markdown"
	  },
	  {
		"foreground": "6a8187",
		"token": "text.plain"
	  },
	  {
		"foreground": "eee8d5",
		"background": "eee8d5",
		"token": "sublimelinter.notes"
	  },
	  {
		"foreground": "93a1a1",
		"background": "93a1a1",
		"token": "sublimelinter.outline.illegal"
	  },
	  {
		"background": "dc322f",
		"token": "sublimelinter.underline.illegal"
	  },
	  {
		"foreground": "839496",
		"background": "839496",
		"token": "sublimelinter.outline.warning"
	  },
	  {
		"background": "b58900",
		"token": "sublimelinter.underline.warning"
	  },
	  {
		"foreground": "657b83",
		"background": "657b83",
		"token": "sublimelinter.outline.violation"
	  },
	  {
		"background": "cb4b16",
		"token": "sublimelinter.underline.violation"
	  }
	],
	"colors": {
	  "editor.foreground": "#586E75",
	  "editor.background": "#FDF6E3",
	  "editor.selectionBackground": "#EEE8D5",
	  "editor.lineHighlightBackground": "#EEE8D5",
	  "editorCursor.foreground": "#000000",
	  "editorWhitespace.foreground": "#EAE3C9"
	}
}

// Textmate
const Textmate = {
	"base": "vs",
	"inherit": true,
	"rules": [
	  {
		"foreground": "0066ff",
		"fontStyle": "italic",
		"token": "comment"
	  },
	  {
		"foreground": "bfbfbf",
		"token": "deco.folding"
	  },
	  {
		"foreground": "0000ff",
		"fontStyle": "bold",
		"token": "keyword"
	  },
	  {
		"foreground": "0000ff",
		"fontStyle": "bold",
		"token": "storage"
	  },
	  {
		"foreground": "0000cd",
		"token": "constant.numeric"
	  },
	  {
		"foreground": "c5060b",
		"fontStyle": "bold",
		"token": "constant"
	  },
	  {
		"foreground": "585cf6",
		"fontStyle": "bold",
		"token": "constant.language"
	  },
	  {
		"foreground": "318495",
		"token": "variable.language"
	  },
	  {
		"foreground": "318495",
		"token": "variable.other"
	  },
	  {
		"foreground": "036a07",
		"token": "string"
	  },
	  {
		"foreground": "26b31a",
		"token": "constant.character.escape"
	  },
	  {
		"foreground": "26b31a",
		"token": "string meta.embedded"
	  },
	  {
		"foreground": "1a921c",
		"token": "meta.preprocessor"
	  },
	  {
		"foreground": "0c450d",
		"fontStyle": "bold",
		"token": "keyword.control.import"
	  },
	  {
		"foreground": "0000a2",
		"fontStyle": "bold",
		"token": "entity.name.function"
	  },
	  {
		"foreground": "0000a2",
		"fontStyle": "bold",
		"token": "support.function.any-method"
	  },
	  {
		"fontStyle": "underline",
		"token": "entity.name.type"
	  },
	  {
		"fontStyle": "italic",
		"token": "entity.other.inherited-class"
	  },
	  {
		"fontStyle": "italic",
		"token": "variable.parameter"
	  },
	  {
		"foreground": "70727e",
		"token": "storage.type.method"
	  },
	  {
		"fontStyle": "italic",
		"token": "meta.section entity.name.section"
	  },
	  {
		"fontStyle": "italic",
		"token": "declaration.section entity.name.section"
	  },
	  {
		"foreground": "3c4c72",
		"fontStyle": "bold",
		"token": "support.function"
	  },
	  {
		"foreground": "6d79de",
		"fontStyle": "bold",
		"token": "support.class"
	  },
	  {
		"foreground": "6d79de",
		"fontStyle": "bold",
		"token": "support.type"
	  },
	  {
		"foreground": "06960e",
		"fontStyle": "bold",
		"token": "support.constant"
	  },
	  {
		"foreground": "21439c",
		"fontStyle": "bold",
		"token": "support.variable"
	  },
	  {
		"foreground": "687687",
		"token": "keyword.operator.js"
	  },
	  {
		"foreground": "ffffff",
		"background": "990000",
		"token": "invalid"
	  },
	  {
		"background": "ffd0d0",
		"token": "invalid.deprecated.trailing-whitespace"
	  },
	  {
		"background": "0000000d",
		"token": "text source"
	  },
	  {
		"background": "0000000d",
		"token": "string.unquoted"
	  },
	  {
		"background": "0000000d",
		"token": "meta.embedded"
	  },
	  {
		"background": "0000000f",
		"token": "text source string.unquoted"
	  },
	  {
		"background": "0000000f",
		"token": "text source text source"
	  },
	  {
		"foreground": "68685b",
		"token": "meta.tag.preprocessor.xml"
	  },
	  {
		"foreground": "888888",
		"token": "meta.tag.metadata.doctype"
	  },
	  {
		"foreground": "888888",
		"token": "meta.tag.metadata.doctype entity"
	  },
	  {
		"foreground": "888888",
		"token": "meta.tag.metadata.doctype string"
	  },
	  {
		"foreground": "888888",
		"token": "meta.tag.metadata.processing.xml"
	  },
	  {
		"foreground": "888888",
		"token": "meta.tag.metadata.processing.xml entity"
	  },
	  {
		"foreground": "888888",
		"token": "meta.tag.metadata.processing.xml string"
	  },
	  {
		"fontStyle": "italic",
		"token": "meta.tag.metadata.doctype string.quoted"
	  },
	  {
		"foreground": "1c02ff",
		"token": "meta.tag"
	  },
	  {
		"foreground": "1c02ff",
		"token": "declaration.tag"
	  },
	  {
		"fontStyle": "bold",
		"token": "entity.name.tag"
	  },
	  {
		"fontStyle": "italic",
		"token": "entity.other.attribute-name"
	  },
	  {
		"foreground": "0c07ff",
		"fontStyle": "bold",
		"token": "markup.heading"
	  },
	  {
		"foreground": "000000",
		"fontStyle": "italic",
		"token": "markup.quote"
	  },
	  {
		"foreground": "b90690",
		"token": "markup.list"
	  }
	],
	"colors": {
	  "editor.foreground": "#000000",
	  "editor.background": "#FFFFFF",
	  "editor.selectionBackground": "#4D97FF54",
	  "editor.lineHighlightBackground": "#00000012",
	  "editorCursor.foreground": "#000000",
	  "editorWhitespace.foreground": "#BFBFBF"
	}
}