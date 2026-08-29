peepdf is a **Python 3.12+ tool to explore PDF files** in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that
a security researcher could need in a PDF analysis without using 3 or 4 tools to make
all the tasks. With peepdf it's possible to see all the objects in the document showing
the suspicious elements, supports all the most used filters and encodings, it can parse different versions of a file, object streams and encrypted files. XML and JSON outputs are natively supported using standard library components without external dependencies. Static analysis, stream extraction, and report generation work out of the box. Optional wrappers for **Javascript execution** ([STPyV8](https://github.com/area1/stpyv8) / PyV8) and **shellcode analysis** ([Pylibemu](https://github.com/buffer/pylibemu) / sctest) are supported when installed. Apart from this it's able to create new PDF files and to modify/obfuscate existent ones.

The main functionalities of peepdf are the following:

**Analysis:**

  * Decodings: hexadecimal, octal, name objects
  * More used filters
  * References in objects and where an object is referenced
  * Strings search (including streams)
  * Physical structure (offsets)
  * Logical tree structure
  * Metadata
  * Modifications between versions (changelog)
  * Compressed objects (object streams)
  * Analysis and modification of Javascript: unescape, replace, join (dynamic evaluation via STPyV8 / PyV8)
  * Shellcode analysis (Libemu python wrapper, pylibemu)
  * Variables (set command)
  * Extraction of old versions of the document
  * Easy extraction of objects, Javascript code, shellcodes (>, >>, $>, $>>)
  * Checking hashes on **VirusTotal** (using the `PEEPDF_VT_KEY` environment variable)
  * XML (`-x`) and JSON (`-j`) structured exports (natively supported via standard library)


**Creation/Modification:**

  * Basic PDF creation
  * Creation of PDF with Javascript executed when the document is opened
  * Creation of object streams to compress objects
  * Embedded PDFs
  * Strings and names obfuscation
  * Malformed PDF output: without endobj, garbage in the header, bad header...
  * Filters modification
  * Objects modification


**Execution modes:**

  * Simple command line execution (`python3 peepdf.py -h` for options overview)
  * **Powerful interactive console** (colorized or not)
  * Batch mode


**TODO:**

  * Embedded PDFs analysis
  * Improving automatic Javascript analysis
  * GUI


**Related articles:**

  * [Spammed CVE-2013-2729 PDF exploit dropping ZeuS-P2P/Gameover](http://eternal-todo.com/blog/cve-2013-2729-exploit-zeusp2p-gameover)
  * [New peepdf v0.2 (Version Black Hat Vegas 2012)](http://eternal-todo.com/blog/peepdf-v0.2-black-hat-usa-arsenal-vegas)
  * [peepdf supports CCITTFaxDecode encoded streams](http://eternal-todo.com/blog/peepdf-ccittfaxdecode-support)
  * [Explanation of the changelog of peepdf for Black Hat Europe Arsenal 2012](http://eternal-todo.com/blog/peepdf-black-hat-arsenal-2012)
  * [How to extract streams and shellcodes from a PDF, the easy way](http://eternal-todo.com/blog/extract-streams-shellcode-peepdf)
  * [Static analysis of a CVE-2011-2462 PDF exploit](http://eternal-todo.com/blog/cve-2011-2462-exploit-analysis-peepdf)
  * [Analysis of a malicious PDF from a SEO Sploit Pack](http://eternal-todo.com/blog/seo-sploit-pack-pdf-analysis)
  * Analysing the [Honeynet Project challenge PDF file](http://www.honeynet.org/challenges/2010_6_malicious_pdf) with peepdf [Part 1](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-i) [Part 2](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-ii)
  * [Analyzing Suspicious PDF Files With Peepdf](http://blog.zeltser.com/post/6780160077/peepdf-malicious-pdf-analysis)


**Included in:**

  * [REMnux](http://zeltser.com/remnux/)
  * [BackTrack 5](https://www.backtrack-linux.com/forensics-auditor/)
  * [Kali Linux](http://www.kali.org/)

**You are free to contribute with feedback, bugs, patches, etc. Any help is welcome. Also, if you really enjoy using peepdf, you think it is worth it and you feel really generous today you can donate some bucks to the project ;) Thanks!**

[![](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=X5RRGLX5DTNKS)