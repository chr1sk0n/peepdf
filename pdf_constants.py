"""Constants and static definition tables for PDF parsing and analysis."""

import os

MAL_ALL = 1
MAL_HEAD = 2
MAL_EOBJ = 3
MAL_ESTREAM = 4
MAL_XREF = 5
MAL_BAD_HEAD = 6
newLine = os.linesep

spacesChars = ['\x00', '\x09', '\x0a', '\x0c', '\x0d', '\x20']
delimiterChars = ['<<', '(', '<', '[', '{', '/', '%']
monitorizedEvents = ['/OpenAction ', '/AA ', '/Names ', '/AcroForm ', '/XFA ']
monitorizedActions = [
    '/JS ',
    '/JavaScript',
    '/Launch',
    '/SubmitForm',
    '/ImportData',
]
monitorizedElements = [
    '/EmbeddedFiles ',
    '/EmbeddedFile',
    '/JBIG2Decode',
    'getPageNthWord',
    'arguments.callee',
    '/U3D',
    '/PRC',
    '/RichMedia',
    '/Flash',
    '.rawValue',
    'keep.previous',
]
jsVulns = [
    'mailto',
    'Collab.collectEmailInfo',
    'util.printf',
    'Collab.getIcon',
    'doc.getTemplate',
    'media.newPlayer',
    'spell.customDictionaryOpen',
    'getAnnots',
    'eval',
]
singUniqueName = ['eval']
bmpVuln = '2.1.1'

vulnsDict = {
    'CVE-2007-5659': ['Collab.collectEmailInfo'],
    'CVE-2008-2992': ['util.printf'],
    'CVE-2009-0658': ['/JBIG2Decode'],
    'CVE-2009-0927': ['Collab.getIcon'],
    'CVE-2009-1492': ['doc.getTemplate'],
    'CVE-2009-1493': ['media.newPlayer'],
    'CVE-2009-3953': ['/U3D'],
    'CVE-2009-3959': ['spell.customDictionaryOpen'],
    'CVE-2009-4324': ['media.newPlayer'],
    'CVE-2010-0188': ['/EmbeddedFile', 'getPageNthWord'],
    'CVE-2010-1297': ['/Flash'],
    'CVE-2010-2883': ['singUniqueName'],
    'CVE-2013-0640': ['arguments.callee', '.rawValue', 'keep.previous'],
    'CVE-2013-0641': ['/PRC'],
}

jsContexts = {'global': ''}
