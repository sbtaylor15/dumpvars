package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
)

var validExtensions = map[string]bool{
	".abc":         true, // ABC notation file
	".ada":         true, // Ada source code file
	".agda":        true, // Agda source code file
	".al":          true, // AL source code file
	".applescript": true, // AppleScript file
	".asa":         true, // ASP source code file
	".asax":        true, // ASP.NET application file
	".ascx":        true, // ASP.NET user control file
	".ashx":        true, // ASP.NET handler file
	".asm":         true, // Assembly language source code file
	".asmx":        true, // ASP.NET web service file
	".asp":         true, // ASP classic source code file
	".au3":         true, // AutoIt script file
	".awk":         true, // Awk script file
	".bas":         true, // BASIC source code file
	".bat":         true, // Batch script file
	".bdy":         true, // BETA source code file
	".bpl":         true, // Delphi package library file
	".c":           true, // C source code file
	".cbl":         true, // COBOL source code file
	".cfm":         true, // ColdFusion Markup Language file
	".cl":          true, // OpenCL source code file
	".clixml":      true, // C++/CLI source code file
	".clj":         true, // Clojure source code file
	".cls":         true, // Visual Basic class file
	".cmd":         true, // Windows Command script file
	".coffee":      true, // CoffeeScript file
	".cpp":         true, // C++ source code file
	".cr":          true, // Crystal source code file
	".cs":          true, // C# source code file
	".cshtml":      true, // C# Razor file
	".cson":        true, // CSON (Coffeescript Object Notation) file
	".css":         true, // Cascading Style Sheets file
	".cu":          true, // CUDA source code file
	".cxx":         true, // C++ source code file
	".d":           true, // D source code file
	".dart":        true, // Dart source code file
	".dbm":         true, // GNU DBM database file
	".dbml":        true, // Database Markup Language file
	".dbpro":       true, // DarkBASIC Pro source code file
	".dbpro3":      true, // DarkBASIC Pro 3 source code file
	".def":         true, // Module-definition file
	".dg":          true, // DG Script file
	".dml":         true, // Data Manipulation Language file
	".do":          true, // Stata script file
	".dsp":         true, // Digital Signal Processor file
	".e":           true, // Eiffel source code file
	".ecl":         true, // ECL source code file
	".edn":         true, // Extensible Data Notation file
	".ejs":         true, // Embedded JavaScript file
	".el":          true, // Emacs Lisp source code file
	".elixir":      true, // Elixir source code file
	".elm":         true, // Elm source code file
	".epl":         true, // Euphoria source code file
	".erl":         true, // Erlang source code file
	".es":          true, // ECMAScript file
	".ex":          true, // Elixir source code file
	".exs":         true, // Elixir script file
	".f":           true, // Fortran source code file
	".f03":         true, // Fortran 2003 source code file
	".f08":         true, // Fortran 2008 source code file
	".f77":         true, // Fortran 77 source code file
	".f90":         true, // Fortran 90 source code file
	".f95":         true, // Fortran 95 source code file
	".feature":     true, // Gherkin feature file
	".fish":        true, // Fish shell script file
	".forth":       true, // Forth source code file
	".fpp":         true, // Fortran preprocessed source code file
	".frt":         true, // Forth source code file
	".fs":          true, // F# source code file
	".fsi":         true, // F# interface file
	".fsx":         true, // F# script file
	".fth":         true, // Forth source code file
	".ftn":         true, // Fortran source code file
	".fy":          true, // Forth source code file
	".fzp":         true, // Fritzing project file
	".gameproj":    true, // GameMaker Studio project file
	".gd":          true, // GDScript source code file
	".ged":         true, // GEDCOM file
	".gemspec":     true, // RubyGem specification file
	".glsl":        true, // OpenGL Shading Language file
	".gml":         true, // GameMaker Language file
	".gms":         true, // GameMaker Studio script file
	".go":          true, // Go source code file
	".gpt":         true, // GPLT script file
	".groovy":      true, // Groovy source code file
	".gs":          true, // Google Apps Script file
	".gy":          true, // Groovy source code file
	".h":           true, // C header file
	".h++":         true, // C++ header file
	".haml":        true, // Haml source code file
	".hbs":         true, // Handlebars source code file
	".hcl":         true, // HashiCorp Configuration Language file
	".hh":          true, // C++ header file
	".hlsl":        true, // High-Level Shading Language file
	".hoon":        true, // Hoon source code file
	".hpp":         true, // C++ header file
	".hs":          true, // Haskell source code file
	".htaccess":    true, // Apache .htaccess file
	".htc":         true, // HTC source code file
	".hx":          true, // Haxe source code file
	".hxml":        true, // Haxe build file
	".hxx":         true, // C++ header file
	".i":           true, // IDL source code file
	".iced":        true, // IcedCoffeeScript file
	".icl":         true, // Clean source code file
	".idc":         true, // IDL source code file
	".ini":         true, // INI configuration file
	".io":          true, // Io source code file
	".j":           true, // J source code file
	".java":        true, // Java source code file
	".jison":       true, // Jison grammar file
	".jl":          true, // Julia source code file
	".js":          true, // JavaScript source code file
	".json":        true, // JSON data file
	".jsp":         true, // JavaServer Pages file
	".jsx":         true, // JSX (JavaScript XML) file
	".julia":       true, // Julia source code file
	".kix":         true, // Kixtart script file
	".kt":          true, // Kotlin source code file
	".l":           true, // Lex source code file
	".less":        true, // Less source code file
	".lfe":         true, // Lisp Flavoured Erlang source code file
	".lgt":         true, // Logtalk source code file
	".lidr":        true, // Literate Haskell source code file
	".liquid":      true, // Liquid template file
	".lisp":        true, // Lisp source code file
	".logtalk":     true, // Logtalk source code file
	".ls":          true, // LiveScript source code file
	".lsp":         true, // Lisp source code file
	".lua":         true, // Lua source code file
	".m":           true, // Objective-C source code file
	".m4":          true, // M4 source code file
	".mak":         true, // Makefile
	".maki":        true, // Mapnik XML file
	".markdown":    true, // Markdown file
	".mathematica": true, // Mathematica source code file
	".matlab":      true, // MATLAB source code file
	".max":         true, // MaxScript source code file
	".md":          true, // Markdown file
	".mel":         true, // Maya Embedded Language script file
	".mi":          true, // Objective-C source code file
	".mib":         true, // SNMP MIB file
	".mk":          true, // Makefile
	".ml":          true, // OCaml source code file
	".mm":          true, // Objective-C++ source code file
	".mo":          true, // Modelica source code file
	".mod":         true, // Modula-2 source code file
	".moo":         true, // MOO source code file
	".moon":        true, // MoonScript source code file
	".mq4":         true, // MQL4 source code file
	".mq5":         true, // MQL5 source code file
	".mqh":         true, // MQL Header file
	".mtml":        true, // MTML markup language file
	".muf":         true, // Multi-User Forth source code file
	".mustache":    true, // Mustache template file
	".n":           true, // Nemerle source code file
	".ncl":         true, // Netsuite script file
	".nim":         true, // Nim source code file
	".nix":         true, // Nix script file
	".nl":          true, // Netsuite script file
	".nse":         true, // Nullsoft Scriptable Install System script file
	".nu":          true, // Nu source code file
	".nut":         true, // Squirrel source code file
	".o":           true, // Object file
	".odin":        true, // Odin source code file
	".one":         true, // OneNote file
	".ops":         true, // Operators source code file
	".org":         true, // Org mode file
	".ox":          true, // Ox source code file
	".oxygene":     true, // Oxygene source code file
	".p":           true, // Pascal source code file
	".p6":          true, // Perl 6 source code file
	".pas":         true, // Pascal source code file
	".pascal":      true, // Pascal source code file
	".pd":          true, // Pure Data patch file
	".php":         true, // PHP source code file
	".php3":        true, // PHP 3 source code file
	".php4":        true, // PHP 4 source code file
	".php5":        true, // PHP 5 source code file
	".phps":        true, // PHP script source file
	".phpt":        true, // PHP test script file
	".phtml":       true, // PHP Hypertext Preprocessor file
	".pig":         true, // Pig script file
	".pike":        true, // Pike source code file
	".pl":          true, // Perl source code file
	".plist":       true, // Property list file
	".plsql":       true, // PL/SQL script file
	".pm":          true, // Perl module file
	".pod":         true, // Perl POD documentation file
	".pot":         true, // Portable Object Template file
	".prc":         true, // Palm Resource file
	".pro":         true, // Prolog source code file
	".proto":       true, // Protocol Buffers file
	".ps1":         true, // PowerShell script file
	".ps1xml":      true, // PowerShell XML format file
	".psm1":        true, // PowerShell module file
	".pug":         true, // Pug source code file
	".purs":        true, // PureScript source code file
	".py":          true, // Python source code file
	".pyc":         true, // Python compiled file
	".pyd":         true, // Python dynamic library file
	".pyi":         true, // Python stub file
	".pyo":         true, // Python optimized file
	".pyt":         true, // Python test file
	".pyx":         true, // Cython source code file
	".qml":         true, // QML source code file
	".r":           true, // R source code file
	".r3":          true, // R3 source code file
	".rake":        true, // Ruby Rakefile
	".rb":          true, // Ruby source code file
	".rbbas":       true, // REALbasic source code file
	".rbi":         true, // Ruby interface file
	".rbx":         true, // Ruby source code file
	".rc":          true, // Resource file
	".rcp":         true, // Eclipse Rich Client Platform file
	".re":          true, // Reason source code file
	".reb":         true, // Rebol script file
	".resx":        true, // .NET Resource file
	".rhtml":       true, // Ruby HTML file
	".rkt":         true, // Racket source code file
	".rktl":        true, // Racket library file
	".robo":        true, // RoboFont extension file
	".rpy":         true, // Ren'Py script file
	".rql":         true, // ReQL query language file
	".rs":          true, // Rust source code file
	".rst":         true, // reStructuredText file
	".ruby":        true, // Ruby source code file
	".s":           true, // Assembly language source code file
	".sage":        true, // Sage source code file
	".scala":       true, // Scala source code file
	".scm":         true, // Scheme source code file
	".scss":        true, // Sass source code file
	".sh":          true, // Shell script file
	".sls":         true, // SaltStack state file
	".sml":         true, // Standard ML source code file
	".sql":         true, // SQL script file
	".srt":         true, // SubRip subtitle file
	".ss":          true, // Scheme source code file
	".st":          true, // Smalltalk source code file
	".stl":         true, // Stereolithography file
	".styl":        true, // Stylus stylesheet file
	".stylus":      true, // Stylus stylesheet file
	".swift":       true, // Swift source code file
	".swm":         true, // StarWriter Master document file
	".t":           true, // Tcl/Tk script file
	".tcl":         true, // Tcl script file
	".tex":         true, // LaTeX source code file
	".textile":     true, // Textile source code file
	".toml":        true, // TOML configuration file
	".ts":          true, // TypeScript source code file
	".tsx":         true, // TypeScript React source code file
	".twig":        true, // Twig template file
	".txl":         true, // TXL source code file
	".v":           true, // Verilog source code file
	".vala":        true, // Vala source code file
	".vapi":        true, // Vala API file
	".vb":          true, // Visual Basic source code file
	".vba":         true, // VBA source code file
	".vbs":         true, // VBScript file
	".vcl":         true, // Varnish Configuration Language file
	".vh":          true, // VHDL source code file
	".vhd":         true, // VHDL source code file
	".vhdl":        true, // VHDL source code file
	".vim":         true, // Vim script file
	".x":           true, // XQuery source code file
	".xaml":        true, // XAML file
	".xht":         true, // XHTML file
	".xhtml":       true, // XHTML file
	".xlsm":        true, // Excel Open XML Macro-Enabled Spreadsheet file
	".xpl":         true, // XProc source code file
	".xsd":         true, // XML Schema Definition file
	".xsl":         true, // XSLT stylesheet file
	".y":           true, // Yacc source code file
	".yaml":        true, // YAML file
	".yang":        true, // YANG data modeling language file
	".yap":         true, // Yapp source code file
	".yml":         true, // YAML file
	".yxx":         true, // Yacc++ source code file
	".zsh":         true, // Z shell script file
}

func isBinaryFile(filepath string) bool {
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("Error opening file: %s\n", err)
		return true
	}
	defer file.Close()

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return true
	}

	contentType := http.DetectContentType(buffer)
	return !strings.HasPrefix(contentType, "text/")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <source_code_directory>")
		return
	}
	algorithmSet := make(map[string]struct{}) // To store unique algorithms
	dir := os.Args[1]

	err := os.Chdir(dir)
	if err != nil {
		fmt.Println("Error changing directory:", err)
		return
	}

	// Load .gitignore rules
	ignorePatterns, err := loadGitIgnore(dir)
	if err != nil {
		fmt.Printf("Error loading .gitignore: %s\n", err)
		return
	}

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if shouldIgnore(dir, path, ignorePatterns, true) {
				// Skip directories based on .gitignore rules
				return filepath.SkipDir
			}
			return nil
		}
		if shouldIgnore(dir, path, ignorePatterns, false) {
			return nil
		}
		processFile(path, algorithmSet)
		return nil
	})
	if err != nil {
		fmt.Printf("Error walking directory: %s\n", err)
	}

	fmt.Println("Unique algorithms found:")
	for alg := range algorithmSet {
		fmt.Println("-", alg)
	}
}

func loadGitIgnore(dir string) (*gitignore.GitIgnore, error) {
	gitIgnorePath := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gitIgnorePath); os.IsNotExist(err) {
		// If .gitignore doesn't exist, return empty patterns
		return gitignore.CompileIgnoreLines(""), nil
	}
	return gitignore.CompileIgnoreFile(gitIgnorePath)
}

func shouldIgnore(root string, path string, ignorePatterns *gitignore.GitIgnore, isDir bool) bool {

	if root == path {
		return false
	}

	relPath := strings.TrimPrefix(path, root+"/")

	if strings.HasSuffix(relPath, ".git") {
		return true
	}

	if !isDir {
		// Check if the file extension is in the list of valid extensions
		ext := strings.ToLower(filepath.Ext(relPath))
		if !validExtensions[ext] {
			return true
		}

		if isBinaryFile(relPath) {
			return true
		}
	}
	return ignorePatterns.MatchesPath(relPath)
}

func processFile(filepath string, algorithmSet map[string]struct{}) {
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("Error opening file: %s\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	algorithmRegex := regexp.MustCompile(`\b(AES|RSA|DES|3DES|MD5|SHA-?([1-3]?\d\d?|4[0-8]?[0-9]|5[0-5]?[0-9]|6[0-4]?[0-9]|65[0-4]?)|Blowfish|RC[45]|ECC|Elliptic\sCurve|PGP|GPG|ChaCha20|Poly1305|HMAC|RC2|Camellia|Whirlpool|Salsa20|Twofish|Argon2|BCrypt|PBKDF2|Scrypt|DSA|Diffie-Hellman|ECDH|EdDSA|Curve25519|Curve448|GOST|SM2|SM3|SM4|ED25519|ed25519)\b`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := algorithmRegex.FindAllString(line, -1)
		for _, match := range matches {
			algorithmSet[match] = struct{}{} // Add match to algorithmSet (unique)
		}
	}
}
