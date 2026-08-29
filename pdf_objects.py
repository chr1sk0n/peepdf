
def _get_pdf_parser():
    from pdf_parser import PDFParser
    return PDFParser()
"""PDF basic object types (primitives, arrays, dictionaries, streams, indirect objects)."""

import hashlib
import os
import re
import struct

from JSAnalysis import analyseJS, isJavascript
from parser_context import get_parser_context
from pdf_constants import (
    bmpVuln,
    delimiterChars,
    jsContexts,
    jsVulns,
    monitorizedActions,
    monitorizedElements,
    monitorizedEvents,
    newLine,
    singUniqueName,
    spacesChars,
    vulnsDict,
)
from PDFCrypto import (
    RC4,
    computeEncryptionKey,
    computeObjectKey,
    computeOwnerPass,
    computeUserPass,
    isOwnerPass,
    isUserPass,
)
from PDFFilters import decodeStream, encodeStream
from PDFUtils import (
    encodeName,
    encodeString,
    escapeString,
    numToHex,
    numToString,
    unescapeString,
)

class PDFObject :
    '''
        Base class for all the PDF objects
    '''
    def __init__(self, raw = None):
        '''
            Constructor of a PDFObject
            
            @param raw: The raw value of the PDF object
        '''
        self.references = []
        self.type = ''
        self.value = ''
        self.rawValue = raw
        self.JSCode = []
        self.uriList = []
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.encryptedValue = raw
        self.encryptionKey = ''
        self.encrypted = False
        self.errors = []
        self.referencesInElements = {}
        self.compressedIn = None
    
    def addError(self, errorMessage):
        '''
            Add an error to the object
            
            @param errorMessage: The error message to be added (string)
        '''
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)
            
    def contains(self, string):
        '''
            Look for the string inside the object content
            
            @param string: A string
            @return: A boolean to specify if the string has been found or not
        '''
        value = str(self.value)
        rawValue = str(self.rawValue)
        encValue = str(self.encryptedValue)
        if re.findall(string,value,re.IGNORECASE) != [] or re.findall(string,rawValue,re.IGNORECASE) != [] or re.findall(string,encValue,re.IGNORECASE) != []:
            return True
        if self.containsJS():
            for js in self.JSCode:
                if re.findall(string,js,re.IGNORECASE) != []:
                    return True
        return False

    def containsJS(self):
        '''
            Method to check if there are Javascript code inside the object
            
            @return: A boolean
        '''
        return self.containsJScode

    def containsURIs(self):
        '''
            Method to check if there are URIs inside the object

            @return: A boolean
        '''
        if self.uriList:
            return True
        else:
            return False

    def encodeChars(self):
        '''
            Encode the content of the object if possible (only for PDFName, PDFString, PDFArray and PDFStreams) 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        return (0,'')
    
    def encrypt(self, password):
        '''
            Encrypt the content of the object if possible 
            
            @param password: The password used to encrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        return (0,'')

    def getCompressedIn(self):
        '''
            Gets the id of the object (object stream) where the actual object is compressed 
            
            @return: The id (int) of the object stream or None if it's not compressed
        '''
        return self.compressedIn
                    
    def getEncryptedValue(self):
        '''
            Gets the encrypted value of the object 
            
            @return: The encrypted value or the raw value if the object is not encrypted
        '''
        return self.encryptedValue    

    def getEncryptionKey(self):
        '''
            Gets the encryption key (password) used to encrypt the object 
            
            @return: The password (string) or an empty string if it's not encrypted
        '''
        return self.encryptionKey

    def getErrors(self):
        '''
            Gets the error messages found while parsing and processing the object 
            
            @return: The array of errors of the object
        '''
        return self.errors

    def getRawValue(self):
        '''
            Gets the raw value of the object 
            
            @return: The raw value of the object, this means without applying filters or decoding characters
        '''
        return self.rawValue

    def getReferences(self):
        '''
            Gets the referenced objects in the actual object 
            
            @return: An array of references in the object (Ex. ['1 0 R','12 0 R'])
        '''
        return self.references
    
    def getReferencesInElements(self):
        '''
            Gets the dependencies between elements in the object and objects in the rest of the document.
            
            @return: A dictionary of dependencies of the object (Ex. {'/Length':[5,'']} or {'/Length':[5,'354']})
        '''
        return self.referencesInElements

    def getStats(self):
        '''
            Gets the statistics of the object 
            
            @return: An array of different statistics of the object (object type, compression, references, etc)
        '''
        stats = {}
        stats['Object'] = self.type
        stats['MD5'] = hashlib.md5(self.value).hexdigest()
        stats['SHA1'] = hashlib.sha1(self.value).hexdigest()
        if self.isCompressed():
            stats['Compressed in'] = str(self.compressedIn)
        else:
            stats['Compressed in'] = None
        stats['References'] = str(self.references)
        if self.containsJScode:
            stats['JSCode'] = True
            if len(self.unescapedBytes) > 0:
                stats['Escaped Bytes'] = True
            else:
                stats['Escaped Bytes'] = False
            if len(self.urlsFound) > 0:
                stats['URLs'] = True
            else:
                stats['URLs'] = False
        else:
            stats['JSCode'] = False
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats
        
    def getType(self):
        '''
            Gets the type of the object 
            
            @return: The object type (bool, null, real, integer, name, string, hexstring, reference, array, dictionary, stream)
        '''
        return self.type

    def getValue(self):
        '''
            Gets the value of the object 
            
            @return: The value of the object, this means after applying filters and/or decoding characters and strings
        '''
        return self.value    

    def isCompressed(self):
        '''
            Specifies if the object is compressed or not 
            
            @return: A boolean
        '''
        if self.compressedIn != None:
            return True
        else:
            return False
                
    def isEncrypted(self):
        '''
            Specifies if the object is encrypted or not 
            
            @return: A boolean
        '''
        return self.encrypted

    def isFaulty(self):
        '''
            Specifies if the object has errors or not 
            
            @return: A boolean
        '''
        if self.errors == []:
            return False
        else:
            return True
    
    def replace(self, string1, string2):
        '''
            Searches the object for the 'string1' and if it's found it's replaced by 'string2' 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        if self.value.find(string1) == -1 and self.rawValue.find(string1) == -1:
            return (-1,'String not found')
        self.value = self.value.replace(string1, string2)
        self.rawValue = self.rawValue.replace(string1, string2)
        ret = self.update()
        return ret
    
    def resolveReferences(self):
        '''
            Replaces the reference to an object by its value if there are references not resolved. Ex. /Length 3 0 R 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        pass

    def setReferencedJSObject(self, value):
        '''
            Modifies the referencedJSObject element

            @param value: The new value (bool)
        '''
        self.referencedJSObject = value
        ret = self.update()
        return ret

    def setCompressedIn(self, id):
        '''
            Sets the object id of the object stream containing the actual object
            
            @param id: The object id (int)
        '''
        self.compressedIn = id

    def setEncryptedValue(self, value):
        '''
            Sets the encrypted value of the object
            
            @param value: The encrypted value (string) 
        '''
        self.encryptedValue = value
        
    def setEncryptionKey(self, password):
        '''
            Sets the password to encrypt/decrypt the object
            
            @param password: The encryption key (string)  
        '''
        self.encryptionKey = password

    def setRawValue(self, newRawValue):
        '''
            Sets the raw value of the object and updates the object if some modification is needed
            
            @param newRawValue: The new raw value (string)
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.rawValue = newRawValue
        ret = self.update()
        return ret
    
    def setReferencesInElements(self, resolvedReferencesDict):
        '''
            Sets the resolved references array
            
            @param resolvedReferencesDict: A dictionary with the resolved references  
        '''
        self.referencesInElements = resolvedReferencesDict

    def setValue(self, newValue):
        '''
            Sets the value of the object
            
            @param newValue: The new value of the object (string)  
        '''
        self.value = newValue
            
    def update(self):
        '''
            Updates the object after some modification has occurred
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encryptedValue = self.rawValue
        return (0,'')

    def toFile(self):
        '''
            Gets the raw or encrypted value of the object to write it to an output file 
            
            @return: The raw/encrypted value of the object (string)
        '''
        if self.encrypted:
            return self.getEncryptedValue()
        else:
            return self.getRawValue()


class PDFBool (PDFObject) :
    '''
        Boolean object of a PDF document
    '''
    def __init__(self, value) :
        self.type = 'bool'
        self.errors = []
        self.references = []
        self.JSCode = []
        self.uriList = []
        self.encrypted = False
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.referencesInElements = {}
        self.value = self.rawValue = self.encryptedValue = value
        self.compressedIn = None


class PDFNull (PDFObject) :
    '''
        Null object of a PDF document
    '''
    def __init__(self, content) :
        self.type = 'null'
        self.errors = []
        self.JSCode = []
        self.uriList = []
        self.compressedIn = None
        self.encrypted = False
        self.value = self.rawValue = self.encryptedValue = content
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.referencesInElements = {}
        self.references = []


class PDFNum (PDFObject) :
    '''
        Number object of a PDF document: can be an integer or a real number.
    '''
    def __init__(self, num) :
        self.errors = []
        self.JSCode = []
        self.uriList = []
        self.compressedIn = None
        self.encrypted = False
        self.value = num
        self.compressedIn = None
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
    
    def replace(self, string1, string2):
        if self.value.find(string1) == -1:
            return (-1,'String not found')
        self.value = self.value.replace(string1, string2)
        ret = self.update()
        return ret
        
    def update(self):
        self.errors = []
        try:
            if self.value.find('.') != -1:
                self.type = 'real'
                self.rawValue = float(self.value)
            else:
                self.type = 'integer'
                self.rawValue = int(self.value)
        except:
            errorMessage = 'Numeric conversion error'
            self.addError(errorMessage)
            return (-1,errorMessage)
        self.encryptedValue = str(self.rawValue)
        return (0,'')
            
    def setRawValue(self, rawValue):
        self.rawValue = rawValue
        
    def setValue(self, value):
        self.value = value
        ret = self.update()
        return ret
    
    def toFile(self):
        return str(self.rawValue)


class PDFName (PDFObject) :
    '''
        Name object of a PDF document
    '''
    def __init__(self, name) :
        self.type = 'name'
        self.errors = []
        self.JSCode = []
        self.uriList = []
        self.references = []
        self.compressedIn = None
        if name[0] == '/':
            self.rawValue = self.value = self.encryptedValue = name
        else:
            self.rawValue = self.value = self.encryptedValue = '/' + name
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.encryptedValue = ''
        self.encrypted = False
        self.referencesInElements = {}
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])

    def update(self):
        self.errors = []
        errorMessage = ''
        self.value = self.rawValue
        self.encryptedValue = self.rawValue
        hexNumbers = re.findall(r'#([0-9a-f]{2})', self.value, re.DOTALL | re.IGNORECASE)
        try:
            for hexNumber in hexNumbers:
                self.value = self.value.replace('#' + hexNumber, chr(int(hexNumber,16)))
        except:
            errorMessage = 'Error in hexadecimal conversion'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')

    def encodeChars(self):
        ret = encodeName(self.value)
        if ret[0] == -1:
            self.addError(ret[1])
            return ret
        else:
            self.rawValue = ret[1]
            return (0,'')


class PDFString (PDFObject) :
    '''
        String object of a PDF document
    '''
    def __init__(self, string) :
        self.type = 'string'
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.value = self.rawValue = self.encryptedValue = string
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.JSCode = []
        self.uriList = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.references = []
        self.referencesInElements = {}
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
        
    def update(self, decrypt = False):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.errors = []
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.rawValue = unescapeString(self.rawValue)
        self.value = self.rawValue
        '''
        self.value = self.value.replace('\\)',')')
        self.value = self.value.replace('\\\\','\\')
        self.value = self.value.replace('\\\r\\\n','')
        self.value = self.value.replace('\\\r','')
        self.value = self.value.replace('\\\n','')
        '''
        octalNumbers = re.findall(r'\\\\([0-7]{1,3})', self.value, re.DOTALL)
        try:
            for octal in octalNumbers:
                #TODO: check!! \\\\?
                self.value = self.value.replace('\\' + octal, chr(int(octal,8)))
        except:
            errorMessage = 'Error in octal conversion'
            self.addError(errorMessage)
            return (-1,errorMessage)
        if isJavascript(self.value) or self.referencedJSObject:
            self.containsJScode = True
            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.value, jsContexts['global'], get_parser_context().manual_analysis)
            if jsErrors != []:
                for jsError in jsErrors:
                    errorMessage = 'Error analysing Javascript: '+jsError
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if self.encrypted and not decrypt:
            ret = self.encrypt()
            if ret[0] == -1:
                return ret
        return (0,'')

    def encodeChars(self):
         ret = encodeString(self.value)
         if ret[0] == -1:
             self.addError(ret[1])
             return ret
         else:
             self.rawValue = ret[1]
             return (0,'')
    
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            self.encryptedValue = RC4(self.rawValue,self.encryptionKey)
        except:
            errorMessage = 'Error encrypting with RC4'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')

    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            cleanString = unescapeString(self.encryptedValue)
            if algorithm == 'RC4':
                self.rawValue = RC4(cleanString,self.encryptionKey)
            elif algorithm == 'AES':
                ret = AES.decryptData(cleanString,self.encryptionKey)
                if ret[0] != -1:
                    self.rawValue = ret[1]
                else:
                    errorMessage = 'AES decryption error: '+ret[1]
                    self.addError(errorMessage)
                    return (-1,errorMessage)
        except:
            errorMessage = 'Error decrypting with '+str(algorithm)
            self.addError(errorMessage)
            return (-1,errorMessage)
        ret = self.update(decrypt = True)
        return (0,'')
    
    def getEncryptedValue(self):
        return '('+escapeString(self.encryptedValue)+')'
    
    def getJSCode(self):
        '''
            Gets the Javascript code of the object 
            
            @return: An array of Javascript code sections
        '''
        return self.JSCode    
    
    def getRawValue(self):
        return '('+escapeString(self.rawValue)+')'
    
    def getUnescapedBytes(self):
        '''
            Gets the escaped bytes of the object unescaped 
            
            @return: An array of unescaped bytes (string)
        '''
        return self.unescapedBytes
    
    def getURLs(self):
        '''
            Gets the URLs of the object 
            
            @return: An array of URLs
        '''
        return self.urlsFound


class PDFHexString (PDFObject) :
    '''
        Hexadecimal string object of a PDF document
    '''
    def __init__(self, hex) : 
        self.asciiValue = ''
        self.type = 'hexstring'
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.value = '' # Value after hex decoding and decryption
        self.rawValue = hex # Hex characters
        self.encryptedValue = hex # Value after hex decoding
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.JSCode = []
        self.uriList = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])        
            
    def update(self, decrypt = False, newHexValue = True):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.errors = []
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        if not decrypt:
            try:
                if newHexValue:
                    # New hexadecimal value
                    self.value = ''
                    tmpValue = self.rawValue
                    if len(tmpValue) % 2 != 0:
                        tmpValue += '0'
                    self.value = tmpValue.decode('hex')
                else:
                    # New decoded value
                    self.rawValue = self.value.encode('hex')
                self.encryptedValue = self.value
            except:
                errorMessage = 'Error in hexadecimal conversion'
                self.addError(errorMessage)
                return (-1,errorMessage)
        if isJavascript(self.value) or self.referencedJSObject:
            self.containsJScode = True
            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.value, jsContexts['global'], get_parser_context().manual_analysis)
            if jsErrors != []:
                for jsError in jsErrors:
                    errorMessage = 'Error analysing Javascript: '+jsError
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if self.encrypted and not decrypt:
            ret = self.encrypt()
            if ret[0] == -1:
                return ret
        return (0,'')

    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            self.encryptedValue = RC4(self.value,self.encryptionKey)
            self.rawValue = self.encryptedValue.encode('hex')
        except:
            errorMessage = 'Error encrypting with RC4'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')
    
    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        try:
            cleanString = unescapeString(self.encryptedValue)
            if algorithm == 'RC4':
                self.value = RC4(cleanString,self.encryptionKey)
            elif algorithm == 'AES':
                ret = AES.decryptData(cleanString,self.encryptionKey)
                if ret[0] != -1:
                    self.value = ret[1]
                else:
                    errorMessage = 'AES decryption error: '+ret[1]
                    self.addError(errorMessage)
                    return (-1,errorMessage)
        except:
            errorMessage = 'Error decrypting with '+str(algorithm)
            self.addError(errorMessage)
            return (-1,errorMessage)
        ret = self.update(decrypt = True)
        return ret

    def getEncryptedValue(self):
        return '<'+self.rawValue+'>'

    def getJSCode(self):
        '''
            Gets the Javascript code of the object 
            
            @return: An array of Javascript code sections
        '''
        return self.JSCode

    def getRawValue(self):
        return '<'+self.rawValue+'>'

    def getUnescapedBytes(self):
        '''
            Gets the escaped bytes of the object unescaped 
            
            @return: An array of unescaped bytes (string)
        '''
        return self.unescapedBytes
    
    def getURLs(self):
        '''
            Gets the URLs of the object 
            
            @return: An array of URLs
        '''
        return self.urlsFound


class PDFReference (PDFObject) :
    '''
        Reference object of a PDF document
    '''
    def __init__(self, id, genNumber = '0') :
        self.type = 'reference'
        self.errors = []
        self.JSCode = []
        self.uriList = []
        self.compressedIn = None
        self.encrypted = False
        self.value = self.rawValue = self.encryptedValue = id + ' ' + genNumber + ' R'
        self.id = id
        self.genNumber = genNumber
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
        
    def update(self):
        self.errors = []
        self.value = self.encryptedValue = self.rawValue
        valueElements = self.rawValue.split()
        if valueElements != []:
            self.id = int(valueElements[0])
            self.genNumber = int(valueElements[1])
        else:
            errorMessage = 'Error getting PDFReference elements'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return (0,'')
    
    def getGenNumber(self):
        '''
            Gets the generation number of the reference
            
            @return: The generation number (int)
        '''
        return self.genNumber
    
    def getId(self):
        '''
            Gets the object id of the reference
            
            @return: The object id (int)
        '''
        return self.id
    
    def setGenNumber(self, newGenNumber):
        '''
            Sets the generation number of the reference
            
            @param newGenNumber: The new generation number (int)
        '''
        self.genNumber = newGenNumber

    def setId(self, newId):
        '''
            Sets the object id of the reference
            
            @param newId: The new object id (int)
        '''
        self.id = newId


class PDFArray (PDFObject) :
    '''
        Array object of a PDF document
    '''
    def __init__(self, rawContent = '', elements = []) :
        self.type = 'array'
        self.errors = []
        self.JSCode = []
        self.uriList = []
        self.compressedIn = None
        self.encrypted = False
        self.encryptedValue = rawContent
        self.rawValue = rawContent
        self.elements = elements
        self.value = ''
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.referencesInElements = {}
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])

    def update(self, decrypt = False):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        errorMessage = ''
        self.errors = []
        self.encryptedValue = '[ '
        self.rawValue = '[ '
        self.value = '[ '
        self.references = []
        self.containsJScode = False
        self.JSCode = []
        self.unescapedBytes = []
        self.urlsFound = []
        for element in self.elements:
            if element != None:
                type = element.getType()
                if type == 'reference':
                    self.references.append(element.getValue())
                elif type == 'dictionary' or type == 'array':
                    self.references += element.getReferences()
                if element.containsJS():
                    self.containsJScode = True
                    self.JSCode += element.getJSCode()
                    self.unescapedBytes += element.getUnescapedBytes()
                    self.urlsFound += element.getURLs()
                if element.isFaulty():
                    for error in element.getErrors():
                        self.addError('Children element contains errors: ' + error)
                if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                    ret = element.encrypt(self.encryptionKey)
                    if ret[0] == -1:
                        errorMessage = 'Error encrypting element'
                        self.addError(errorMessage)
                self.encryptedValue += str(element.getEncryptedValue()) + ' '
                self.rawValue += str(element.getRawValue()) + ' '
                self.value += element.getValue() + ' '
            else:
                errorMessage = 'None elements'
                self.addError(errorMessage)
        self.encryptedValue = self.encryptedValue[:-1] + ' ]'
        self.rawValue = self.rawValue[:-1] + ' ]'
        self.value = self.value[:-1] + ' ]'
        if errorMessage != '':
            return (-1,'Errors while updating PDFArray')
        else:
            return (0,'')
        
    def addElement(self, element):
        '''
            Adds an element to the array
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements.append(element)
        ret = self.update()
        return ret
        
    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''  
        errorMessage = ''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        decryptedElements = []
        for element in self.elements:
            if element != None:
                type = element.getType()
                if type in ['string','hexstring','array','dictionary']:
                    ret = element.decrypt(self.encryptionKey, algorithm)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(errorMessage)
                decryptedElements.append(element)
        self.elements = decryptedElements
        ret = self.update(decrypt = True)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret

    def encodeChars(self):
        errorMessage = ''
        encodedElements = []
        for element in self.elements:
            if element != None:
                type = element.getType()
                if type in ['string','name','array','dictionary']:
                    ret = element.encodeChars()
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(errorMessage)
                encodedElements.append(element)
        self.elements = encodedElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
        
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        ret = self.update()
        return ret
        
    def getElementByName(self, name):
        '''
            Gets the dictionary elements with the given name
            
            @param name: The name
            @return: An array of elements
        '''
        retElements = []
        for element in self.elements:
            if element != None:
                if element.getType() == 'dictionary' or element.getType() == 'array':
                    retElements += element.getElementByName(name)
            else:
                errorMessage = 'None elements'
                self.addError(errorMessage)
        return retElements
    
    def getElementRawValues(self):
        '''
            Gets the raw values of each element
            
            @return: An array of values
        '''
        values = []
        for element in self.elements:
            if element != None:
                values.append(element.getRawValue())
            else:
                values.append(None)
                errorMessage = 'None elements'
                self.addError(errorMessage)
        return values

    def getElementValues(self):
        '''
            Gets the values of each element
            
            @return: An array of values
        '''
        values = []
        for element in self.elements:
            if element != None:
                values.append(element.getValue())
            else:
                values.append(None)
                errorMessage = 'None elements'
                self.addError(errorMessage)
        return values

    def getElements(self):
        '''
            Gets the elements of the array object
            
            @return: An array of PDFObject elements
        '''
        return self.elements

    def getNumElements(self):
        '''
            Gets the number of elements of the array
            
            @return: The number of elements (int)
        '''
        return len(self.elements)

    def hasElement(self, name):
        '''
            Specifies if the array contains the element with the given name
            
            @param name: The element
            @return: A boolean
        '''
        for element in self.elements:
            if element != None:
                if element.getType() == 'dictionary':
                    if element.hasElement(name):
                        return True
                elif element.getValue() == name:
                    return True
            else:
                errorMessage = 'None elements'
                self.addError(errorMessage)
        else:
            return False

    def replace(self, string1, string2):
        errorMessage = ''
        stringFound = False
        newElements = []
        if self.rawValue.find(string1) != -1:
            self.rawValue = self.rawValue.replace(string1, string2)
            stringFound = True
            if errorMessage == 'String not found':
                errorMessage = ''
        for element in self.elements:
            if element != None:
                ret = element.replace(string1, string2)
                if ret[0] == -1:
                    if ret[1] != 'String not found' or not stringFound:
                        errorMessage = ret[1]
                else:
                    stringFound = True
                    if errorMessage == 'String not found':
                        errorMessage = ''
                newElements.append(element)
            else:
                errorMessage = 'None element while replacing strings'
                self.addError('None element')
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
    
    def setElements(self, newElements):
        '''
            Sets the array of elements
            
            @param newElements: The new array of elements
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements = newElements
        ret = self.update()
        return ret


class PDFDictionary (PDFObject):
    def __init__(self, rawContent = '', elements = None, rawNames = None) :
        elements = {} if elements is None else elements
        rawNames = {} if rawNames is None else rawNames
        self.type = 'dictionary'
        self.dictType = ''
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.value = ''
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.JSCode = []
        self.uriList = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencedJSObjects = []
        self.referencesInElements = {}
        self.rawValue = rawContent
        self.encryptedValue = rawContent
        self.rawNames = rawNames
        self.elements = elements
        self.numElements = len(self.elements)
        self.references = []
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
    
    def update(self, decrypt = False):
        '''
            Updates the object after some modification has occurred
            
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.errors = []
        self.references = []
        self.referencedJSObjects = []
        self.containsJScode = False
        self.JSCode = []
        self.dictType = ''
        self.unescapedBytes = []
        self.urlsFound = []
        self.uriList = []
        errorMessage = ''
        self.value = '<< '
        self.rawValue = '<< '
        self.encryptedValue = '<< '
        keys = list(self.elements.keys())
        values = list(self.elements.values())
        for i in range(len(keys)):
            if values[i] == None:
                errorMessage = 'Non-existing value for key "'+str(keys[i])+'"'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                    valueObject = PDFString('')
                else:
                    return (-1,errorMessage)
            else:
                valueObject = values[i]
            v = valueObject.getValue()
            type = valueObject.getType()
            if keys[i] == '/Type':
                self.dictType = v
            elif keys[i] == '/S':
                if self.dictType == '':
                    self.dictType = '/Action ' + v
                else:
                    self.dictType += ' ' + v
            elif keys[i] == '/URI' and v:
                self.uriList.append(v)
            if type == 'reference':
                self.references.append(v)
                if keys[i] == '/JS':
                    self.referencedJSObjects.append(valueObject.getId())
            elif type == 'dictionary' or type == 'array':
                self.references += valueObject.getReferences()
            if valueObject.containsJS() or (keys[i] == '/JS' and type != 'reference'):
                if not valueObject.containsJS():
                    valueObject.setReferencedJSObject(True)
                self.containsJScode = True
                self.JSCode += valueObject.getJSCode()
                self.unescapedBytes += valueObject.getUnescapedBytes()
                self.urlsFound += valueObject.getURLs()
            if valueObject.containsURIs():
                self.uriList += valueObject.getURIs()
            if valueObject.isFaulty():
                for error in valueObject.getErrors():
                    self.addError('Children element contains errors: ' + error)
            if keys[i] in self.rawNames:
                rawName = self.rawNames[keys[i]]
                rawValue = rawName.getRawValue()
            else:
                rawValue = keys[i]
                self.rawNames[keys[i]] = PDFName(keys[i][1:])
            if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                ret = valueObject.encrypt(self.encryptionKey)
                if ret[0] == -1:
                    errorMessage = 'Error encrypting element'
                    self.addError(errorMessage)
            self.encryptedValue += rawValue + ' ' + str(valueObject.getEncryptedValue()) + newLine
            self.rawValue += rawValue + ' ' + str(valueObject.getRawValue()) + newLine
            self.value += keys[i] + ' ' + v + newLine
        self.encryptedValue = self.encryptedValue[:-1] + ' >>'
        self.rawValue = self.rawValue[:-1] + ' >>'
        self.value = self.value[:-1] + ' >>'
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')
                
    def decrypt(self, password = None, algorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.encrypted = True
        errorMessage = ''
        if password != None:
            self.encryptionKey = password
        decryptedElements = {}
        for key in self.elements:
            object = self.elements[key]
            objectType = object.getType()
            if objectType in ['string','hexstring','array','dictionary']:
                ret = object.decrypt(self.encryptionKey, algorithm)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
            decryptedElements[key] = object
        self.elements = decryptedElements
        ret = self.update(decrypt = True)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
    
    def delElement(self, name, update = True):
        '''
            Removes the element from the dictionary
            
            @param name: The element to remove
            @param update: A boolean indicating if it's necessary an update of the object. By default: True.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        if name in self.elements:
            del(self.elements[name])
            if update:
                ret = self.update()
                return ret
            return (0,'')
        else:
            return (-1,'Element not found')

    def encodeChars(self):
        encodedElements = {}
        errorMessage = ''
        for key in self.elements:
            rawName = self.rawNames[key]
            rawName.encodeChars()
            self.rawNames[key] = rawName
            object = self.elements[key]
            objectType = object.getType()
            if objectType in ['string','name','array','dictionary']:
                ret = object.encodeChars()
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
            encodedElements[key] = object
        self.elements = encodedElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
        
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        ret = self.update()
        return ret

    def getDictType(self):
        '''
            Gets the type of dictionary
            
            @return: The dictionary type (string)
        '''
        return self.dictType

    def getElement(self, name):
        '''
            Gets the element of the dictionary with the given name
           
            @param name: The name of element
            @return: The PDFObject or None if it's not found
        '''
        if name in self.elements:
            return self.elements[name]
        else:
            return None

    def getElementByName(self, name, recursive = False):
        '''
            Gets the elements with the given name
            
            @param name: The name
            @param recursive: A boolean indicating if the search is recursive or not. By default: False.
            @return: A PDFObject if recursive = False and an array of PDFObjects if recursive = True.
        '''
        retElements = []
        if name in self.elements:
            if recursive:
                retElements.append(self.elements[name])
            else:
                return self.elements[name]
        if recursive:
            for element in list(self.elements.values()):
                if element != None and (element.getType() == 'dictionary' or element.getType() == 'array'):
                    retElements += element.getElementByName(name)
        return retElements
    
    def getElements(self):
        '''
            Gets the elements of the array object
            
            @return: An array of PDFObject elements
        '''
        return self.elements
        
    def getJSCode(self):
        '''
            Gets the Javascript code of the object 
            
            @return: An array of Javascript code sections
        '''
        return self.JSCode
    
    def getNumElements(self):
        '''
            Gets the number of elements of the array
            
            @return: The number of elements (int)
        '''
        return len(self.elements)    

    def getReferencedJSObjectIds(self):
        '''
            Gets the object ids of the referenced objects which contain Javascript code

            @return: An array of object ids
        '''
        return self.referencedJSObjects

    def getStats(self):
        stats = {}
        stats['Object'] = self.type
        stats['MD5'] = hashlib.md5(self.value).hexdigest()
        stats['SHA1'] = hashlib.sha1(self.value).hexdigest()
        if self.isCompressed():
            stats['Compressed in'] = str(self.compressedIn)
        else:
            stats['Compressed in'] = None
        stats['References'] = str(self.references)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        if self.dictType != '':
            stats['Type'] = self.dictType
        else:
            stats['Type'] = None
        if '/Subtype' in self.elements:
            stats['Subtype'] = self.elements['/Subtype'].getValue()
        else:
            stats['Subtype'] = None
        if '/S' in self.elements:
            stats['Action type'] = self.elements['/S'].getValue()
        else:
            stats['Action type'] = None
        if self.containsJScode:
            stats['JSCode'] = True
            if len(self.unescapedBytes) > 0:
                stats['Escaped Bytes'] = True
            else:
                stats['Escaped Bytes'] = False
            if len(self.urlsFound) > 0:
                stats['URLs'] = True
            else:
                stats['URLs'] = False
        else:
            stats['JSCode'] = False
        return stats
            
    def getUnescapedBytes(self):
        '''
            Gets the escaped bytes of the object unescaped 
            
            @return: An array of unescaped bytes (string)
        '''
        return self.unescapedBytes

    def getURIs(self):
        '''
            Gets the URIs of the object

            @return: An array of URIs
        '''
        return self.uriList

    def getURLs(self):
        '''
            Gets the URLs of the object 
            
            @return: An array of URLs
        '''
        return self.urlsFound
        
    def hasElement(self, name):
        '''
            Specifies if the dictionary contains the element with the given name
            
            @param name: The element
            @return: A boolean
        '''
        if name in self.elements:
            return True
        else:
            return False
    
    def replace(self, string1, string2):
        newElements = {}
        stringFound = False
        errorMessage = ''
        for key in self.elements:
            if key.find(string1) != -1:
                newKey = key.replace(string1, string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            else:
                newKey = key
            newObject = self.elements[key]
            if newObject != None:
                ret = newObject.replace(string1, string2)
                if ret[0] == -1:
                    if ret[1] != 'String not found' or not stringFound:
                        errorMessage = ret[1]
                else:
                    stringFound = True
                    if errorMessage == 'String not found':
                        errorMessage = ''
                newElements[newKey] = newObject
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret

    def setElement(self, name, value, update = True):
        '''
            Sets the element with the given name to the given value. If it does not exist a new element is created.
            
            @param name: The element to add or modify
            @param value: The new value of the element 
            @param update: A boolean indicating if it's necessary an update of the object. By default: True.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements[name] = value
        if update:
            ret = self.update()
            return ret
        return (0,'')

    def setElements(self, newElements):
        '''
            Sets the dictionary of elements
            
            @param newElements: The new dictionary of elements
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.elements = newElements
        ret = self.update()
        return ret

    def setElementValue(self, name, value, update = True):
        '''
            Sets the value of the element with the given name.
            
            @param name: The element to modify
            @param value: The new value of the element 
            @param update: A boolean indicating if it's necessary an update of the object. By default: True.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        if name in self.elements:
            self.elements[name].setValue(value)
            if update:
                ret = self.update()
                return ret
            return (0,'')
        else:
            return (-1,'Element not found')


class PDFStream (PDFDictionary) :
    '''
        Stream object of a PDF document
    '''
    def __init__(self, rawDict = '', rawStream = '', elements = None, rawNames = None) :
        elements = {} if elements is None else elements
        rawNames = {} if rawNames is None else rawNames
        self.type = 'stream'
        self.dictType = ''
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.decodedStream = ''
        self.encodedStream = ''
        self.encryptedValue = rawDict
        self.rawValue = rawDict
        self.rawNames = rawNames
        self.elements = elements
        self.value = ''
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.rawStream = rawStream
        self.encryptedStream = rawStream
        self.xrefStream = False
        self.newFilters = False
        self.deletedFilters = False
        self.modifiedStream = False
        self.modifiedRawStream = True
        self.JSCode = []
        self.uriList = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.references = []
        self.size = 0
        self.filter = None
        self.filterParams = None
        self.file = None
        self.isEncodedStream = False
        self.decodingError = False
        if elements == {}:
            errorMessage = 'No dictionary in stream object'
            if get_parser_context().force_mode:
                self.addError(errorMessage)
            else:
                raise Exception(errorMessage)
        ret = self.update()
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])

    def update(self, onlyElements=False, decrypt=False, algorithm='RC4'):
        '''
            Updates the object after some modification has occurred
            
            @param onlyElements: A boolean indicating if it's only necessary to update the stream dictionary or also the stream itself. By default: False (stream included).
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @param algorithm: A string indicating the algorithm to use for decryption
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.value = '<< '
        self.rawValue = '<< '
        self.encryptedValue = '<< '
        keys = list(self.elements.keys())
        values = list(self.elements.values())
        if not onlyElements:
            self.references = []
            self.errors = []
            self.JSCode = []
            self.unescapedBytes = []
            self.urlsFound = []
            self.containsJScode = False
            self.decodingError = False
            
        # Dictionary
        if '/Type' in self.elements and self.elements['/Type'] != None:
            if self.elements['/Type'].getValue() == '/XRef':
                self.xrefStream = True
        if '/Length' in self.elements:
            length = self.elements['/Length']
            if length != None:
                if length.getType() == 'integer':
                    self.size = length.getRawValue()
                elif length.getType() == 'reference':
                    self.updateNeeded = True
                    self.referencesInElements['/Length'] = [length.getId(),'']
                else:
                    if get_parser_context().force_mode:
                        self.addError('No permitted type for /Length element')
                    else:
                        return (-1,'No permitted type for /Length element')
            else:
                if get_parser_context().force_mode:
                    self.addError('None /Length element')
                else:
                    return (-1,'None /Length element')
        else:
            if get_parser_context().force_mode:
                self.addError('Missing /Length in stream object')
            else:
                return (-1,'Missing /Length in stream object')
            
        if '/F' in self.elements:
            self.file = self.elements['/F'].getValue()
            if os.path.exists(self.file):
                self.rawStream = open(self.file,'rb').read()
            else:
                if get_parser_context().force_mode:
                    self.addError('File "'+self.file+'" does not exist (/F)')
                    self.rawStream = ''
                else:
                    return (-1,'File "'+self.file+'" does not exist (/F)')
            
        if '/Filter' in self.elements:
            self.filter = self.elements['/Filter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        elif '/FFilter' in self.elements:
            self.filter = self.elements['/FFilter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        else:
            self.encodedStream = ''
            if self.deletedFilters or self.modifiedStream:
                self.rawStream = self.decodedStream
            elif not self.encrypted:
                self.decodedStream = self.rawStream
            self.isEncodedStream = False
        if self.isEncodedStream:
            if '/DecodeParms' in self.elements:
                self.filterParams = self.elements['/DecodeParms']
            elif '/FDecodeParms' in self.elements:
                self.filterParams = self.elements['/FDecodeParms']
            elif '/DP' in self.elements:
                self.filterParams = self.elements['/DP']
            else:
                self.filterParams = None
                
        for i in range(len(keys)):
            valueElement = values[i]
            if valueElement == None:
                errorMessage = 'Stream dictionary has a None value'
                self.addError(errorMessage)
                valueElement = PDFString('')
            v = valueElement.getValue()
            type = valueElement.getType()
            if type == 'reference':
                if v not in self.references: 
                    self.references.append(v)
            elif type == 'dictionary' or type == 'array':
                self.references = list(set(self.references + valueElement.getReferences()))
            if valueElement.containsJS():
                self.containsJScode = True
                self.JSCode = list(set(self.JSCode + valueElement.getJSCode()))
                self.unescapedBytes = list(set(self.unescapedBytes + valueElement.getUnescapedBytes()))
                self.urlsFound = list(set(self.urlsFound + valueElement.getURLs()))
            if valueElement.isFaulty():
                for error in valueElement.getErrors():
                    self.addError('Children element contains errors: ' + error)
            if keys[i] in self.rawNames:
                rawName = self.rawNames[keys[i]]
                rawValue = rawName.getRawValue()
            else:
                rawValue = keys[i]
                self.rawNames[keys[i]] = PDFName(keys[i][1:])
            if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                ret = valueElement.encrypt(self.encryptionKey)
                if ret[0] == -1:
                    errorMessage = ret[1]+' in child element'
                    self.addError(errorMessage)
            self.encryptedValue += rawValue + ' ' + str(valueElement.getEncryptedValue()) + newLine
            self.rawValue += rawValue + ' ' + str(valueElement.getRawValue()) + newLine
            self.value += keys[i] + ' ' + v + newLine
        self.encryptedValue = self.encryptedValue[:-1] + ' >>'
        self.rawValue = self.rawValue[:-1] + ' >>'
        self.value = self.value[:-1] + ' >>'
        
        if not onlyElements:
            # Stream
            if self.deletedFilters or self.newFilters or self.modifiedStream or self.modifiedRawStream or self.encrypted:
                if self.deletedFilters:
                    if self.encrypted:
                        try:
                            self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                        except:
                            errorMessage = 'Error encrypting stream with RC4'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        self.size = len(self.rawStream)
                    else:
                        self.size = len(self.decodedStream)
                elif self.newFilters:
                    ret = self.encode()
                    if ret[0] != -1:
                        if self.encrypted:
                            try:
                                self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            self.size = len(self.encodedStream)
                elif self.modifiedStream:
                    refs = re.findall(r'(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                    if refs != []:
                        self.references += refs
                        self.references = list(set(self.references))
                    if isJavascript(self.decodedStream) or self.referencedJSObject:
                        self.containsJScode = True
                        self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], get_parser_context().manual_analysis)
                        if jsErrors != []:
                            for jsError in jsErrors:
                                errorMessage = 'Error analysing Javascript: '+jsError
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                    if self.isEncodedStream:
                        ret = self.encode()
                        if ret[0] != -1:
                            if self.encrypted:
                                try:
                                    self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                                except:
                                    errorMessage = 'Error encrypting stream with RC4'
                                    if get_parser_context().force_mode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                                self.size = len(self.rawStream)
                            else:
                                self.size = len(self.encodedStream)
                    else:
                        if self.encrypted:
                            try:
                                self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            self.size = len(self.decodedStream)
                elif self.modifiedRawStream:
                    if len(self.encodedStream) > 0 or len(self.decodedStream) > 0:
                        self.cleanStream()
                    if not self.updateNeeded:
                        if self.encrypted:
                            if self.isEncodedStream:
                                if decrypt:
                                    try:
                                        if algorithm == 'RC4':
                                            self.encodedStream = RC4(self.encodedStream,self.encryptionKey)
                                        elif algorithm == 'AES':
                                            ret = AES.decryptData(self.encodedStream,self.encryptionKey)
                                            if ret[0] != -1:
                                                self.encodedStream = ret[1]
                                            else:
                                                errorMessage = 'AES decryption error: '+ret[1]
                                                if get_parser_context().force_mode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1,errorMessage)
                                    except:
                                        errorMessage = 'Error decrypting stream with '+str(algorithm)
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                                else:
                                    self.encodedStream = self.rawStream
                                    try:
                                        self.rawStream = RC4(self.rawStream,self.encryptionKey)
                                    except:
                                        errorMessage = 'Error encrypting stream with RC4'
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                                self.decode()
                            else:
                                if not decrypt:
                                    self.decodedStream = self.rawStream                                
                                try:
                                    rc4Result = RC4(self.rawStream,self.encryptionKey)
                                    if decrypt:
                                        self.decodedStream = rc4Result
                                    else:
                                        self.rawStream = rc4Result
                                except:
                                    errorMessage = 'Error encrypting stream with RC4'
                                    if get_parser_context().force_mode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                        else:
                            if self.isEncodedStream:
                                self.decode()
                        self.size = len(self.rawStream)
                        if not self.isFaultyDecoding():
                            refs = re.findall(r'(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                            if refs != []:
                                self.references += refs
                                self.references = list(set(self.references))
                            if isJavascript(self.decodedStream) or self.referencedJSObject:
                                self.containsJScode = True
                                self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], get_parser_context().manual_analysis)
                                if jsErrors != []:
                                    for jsError in jsErrors:
                                        errorMessage = 'Error analysing Javascript: '+jsError
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                else:
                    if not decrypt:
                        try:
                            if self.isEncodedStream:
                                self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                            else:
                                self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                        except:
                            errorMessage = 'Error encrypting stream with RC4'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        self.size = len(self.rawStream)
                    else:
                        if self.isEncodedStream:
                            try:
                                if algorithm == 'RC4':
                                    self.encodedStream = RC4(self.encodedStream,self.encryptionKey)
                                elif algorithm == 'AES':
                                    ret = AES.decryptData(self.encodedStream,self.encryptionKey)
                                    if ret[0] != -1:
                                        self.encodedStream = ret[1]
                                    else:
                                        errorMessage = 'AES decryption error: '+ret[1]
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                            except:
                                errorMessage = 'Error decrypting stream with '+str(algorithm)
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.decode()
                        else:
                            try:
                                if algorithm == 'RC4':
                                    self.decodedStream = RC4(self.decodedStream,self.encryptionKey)
                                elif algorithm == 'AES':
                                    ret = AES.decryptData(self.decodedStream,self.encryptionKey)
                                    if ret[0] != -1:
                                        self.decodedStream = ret[1]
                                    else:
                                        errorMessage = 'AES decryption error: '+ret[1]
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                            except:
                                errorMessage = 'Error decrypting stream with '+str(algorithm)
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                        if not self.isFaultyDecoding():
                            refs = re.findall(r'(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                            if refs != []:
                                self.references += refs
                                self.references = list(set(self.references))
                            if isJavascript(self.decodedStream) or self.referencedJSObject:
                                self.containsJScode = True
                                self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], get_parser_context().manual_analysis)
                                if jsErrors != []:
                                    for jsError in jsErrors:
                                        errorMessage = 'Error analysing Javascript: '+jsError
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                if not self.modifiedRawStream:
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
                    errors = self.errors
                    try:
                        self.setElement('/Length',PDFNum(str(self.size)))
                        self.errors += errors
                    except:
                        errorMessage = 'Error creating PDFNum'
                        if get_parser_context().force_mode:
                            self.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                else:
                    self.modifiedRawStream = False
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
        if self.errors != []:
            return (-1,self.errors[-1])
        else:
            return (0,'')

    def cleanStream(self):
        '''
            Cleans the start and end of the stream
        '''
        if self.isEncodedStream:
            stream = self.encodedStream
            tmpStream = self.encodedStream
        else:
            stream = self.decodedStream
            tmpStream = self.decodedStream
        '''
        garbage = len(stream) - self.size
        if garbage > 0:
            for i in range(len(tmpStream)):
                if garbage == 0:
                    break
                if tmpStream[i] == '\r' or tmpStream[i] == '\n':
                    stream = stream[1:]
                    garbage -= 1
                else:
                    break
            for i in range(len(tmpStream)-1,0,-1):
                if garbage == 0:
                    break
                if tmpStream[i] == '\r' or tmpStream[i] == '\n':
                    stream = stream[:-1]
                    garbage -= 1
                else:
                    break
        '''
        streamLength = len(stream)
        '''
        if streamLength > 1 and stream[:2] == '\r\n':
            stream = stream[2:]
            streamLength -= 2
        elif streamLength > 0 and (stream[0] == '\r' or stream[0] == '\n'):
            stream = stream[1:]
            streamLength -= 1
        '''
        if streamLength > 1 and stream[-2:] == '\r\n':
            stream = stream[:-2]
        elif streamLength > 0 and (stream[-1] == '\r' or stream[-1] == '\n'):
            stream = stream[:-1]
        if self.isEncodedStream:
            self.encodedStream = stream
        else:
            self.decodedStream = stream

    def contains(self, string):
        value = str(self.value)
        rawValue = str(self.rawValue)
        encValue = str(self.encryptedValue)
        rawStream = str(self.rawStream)
        encStream = str(self.encodedStream)
        decStream = str(self.decodedStream)
        if re.findall(string,value,re.IGNORECASE) != [] or re.findall(string,rawValue,re.IGNORECASE) != [] or re.findall(string,encValue,re.IGNORECASE) != [] or re.findall(string,rawStream,re.IGNORECASE) != [] or re.findall(string,encStream,re.IGNORECASE) != [] or re.findall(string,decStream,re.IGNORECASE) != []:
            return True
        if self.containsJS():
            for js in self.JSCode:
                if re.findall(string,js,re.IGNORECASE) != []:
                    return True
        return False        
    
    def decode (self) :
        '''
            Decodes the stream and stores the result in decodedStream 
            
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        errorMessage = ''
        if len(self.rawStream) > 0:
            if self.isEncodedStream:
                if self.filter == None:
                    errorMessage = 'Bad /Filter element'
                    self.addError(errorMessage)
                    return (-1,errorMessage)
                filterType = self.filter.getType()
                if self.filterParams != None:
                    filterParamsType = self.filterParams.getType()
                if filterType == 'name':
                    if self.filterParams == None:
                        ret = decodeStream(self.encodedStream, self.filter.getValue(), self.filterParams)
                        if ret[0] == -1:
                            if self.rawStream != self.encodedStream:
                                ret = decodeStream(self.rawStream, self.filter.getValue(), self.filterParams)
                            if ret[0] == -1:
                                self.decodingError = True
                                errorMessage = 'Decoding error: '+ret[1]
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                    self.decodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.decodedStream = ret[1]
                        else:
                            self.decodedStream = ret[1]
                    elif filterParamsType == 'dictionary':
                        ret = decodeStream(self.encodedStream, self.filter.getValue(), self.filterParams.getElements())            
                        if ret[0] == -1:
                            if self.rawStream != self.encodedStream:
                                ret = decodeStream(self.rawStream, self.filter.getValue(), self.filterParams.getElements())
                            if ret[0] == -1:
                                self.decodingError = True
                                errorMessage = 'Decoding error: '+ret[1]
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                    self.decodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.decodedStream = ret[1]
                        else:
                            self.decodedStream = ret[1]
                    else:
                        if get_parser_context().force_mode:
                            errorMessage = 'Filter parameters type is not valid'
                            self.addError(errorMessage)
                            self.decodedStream = ''
                        else:
                            return (-1,'Filter parameters type is not valid')
                elif filterType == 'array':
                    self.decodedStream = self.encodedStream
                    filterElements = self.filter.getElements()
                    for i in range(len(filterElements)):
                        filter = filterElements[i]
                        if filter == None:
                            if get_parser_context().force_mode:
                                errorMessage = 'Bad /Filter element in PDFArray'
                                self.addError(errorMessage)
                                continue
                            return (-1,'Bad /Filter element in PDFArray')
                        if filter.getType() == 'name':
                            if self.filterParams == None:
                                ret = decodeStream(self.decodedStream, filter.getValue(), self.filterParams)
                                if ret[0] == -1:
                                    if i == 0 and self.rawStream != self.encodedStream:
                                        ret = decodeStream(self.rawStream, filter.getValue(), self.filterParams)
                                    if ret[0] == -1:
                                        self.decodingError = True
                                        errorMessage = 'Decoding error: '+ret[1]
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                            self.decodedStream = ''
                                        else:
                                            return (-1,errorMessage)
                                    else:
                                        self.decodedStream = ret[1]
                                else:
                                    self.decodedStream = ret[1]
                            elif filterParamsType == 'array':
                                paramsArray = self.filterParams.getElements()
                                if i >= len(paramsArray):
                                    paramsObj = None
                                    paramsDict = {}
                                else:
                                    paramsObj = paramsArray[i]
                                    if paramsObj == None:
                                        if get_parser_context().force_mode:
                                            errorMessage = 'Bad /FilterParms element in PDFArray'
                                            self.addError(errorMessage)
                                            continue
                                        return (-1,'Bad /FilterParms element in PDFArray')
                                    paramsObjType = paramsObj.getType()
                                    if paramsObjType == 'dictionary':
                                        paramsDict = paramsObj.getElements()
                                    else:
                                        paramsDict = {}
                                ret = decodeStream(self.decodedStream, filter.getValue(), paramsDict)
                                if ret[0] == -1:
                                    if i == 0 and self.rawStream != self.encodedStream:
                                        ret = decodeStream(self.rawStream, filter.getValue(), paramsDict)
                                    if ret[0] == -1:
                                        self.decodingError = True
                                        errorMessage = 'Decoding error: '+ret[1]
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                            self.decodedStream = ''
                                        else:
                                            return (-1,errorMessage)
                                    else:
                                        self.decodedStream = ret[1]
                                else:
                                    self.decodedStream = ret[1]
                            else:
                                if get_parser_context().force_mode:
                                    errorMessage = 'One of the filters parameters type is not valid'
                                    self.addError(errorMessage)
                                    self.decodedStream = ''
                                else:
                                    return (-1,'One of the filters parameters type is not valid')
                        else:
                            if get_parser_context().force_mode:
                                errorMessage = 'One of the filters type is not valid'
                                self.addError(errorMessage)
                                self.decodedStream = ''
                            else:
                                return (-1,'One of the filters type is not valid')
                else:
                    if get_parser_context().force_mode:
                        errorMessage = 'Filter type is not valid'
                        self.addError(errorMessage)
                        self.decodedStream = ''
                    else:
                        return (-1,'Filter type is not valid')
                if errorMessage != '':
                    return (-1,errorMessage)
                else:
                    return (0,'')
            else:
                return (-1,'Not encoded stream')
        else:
            return (-1,'Empty stream')            

    def decrypt(self, password = None, strAlgorithm = 'RC4', altAlgorithm = 'RC4'):
        '''
            Decrypt the content of the object if possible 
            
            @param password: The password used to decrypt the object. It's dependent on the object.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        errorMessage = ''
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        decryptedElements = {}
        for key in self.elements:
            object = self.elements[key]
            objectType = object.getType()
            if objectType in ['string','hexstring','array','dictionary']:
                ret = object.decrypt(self.encryptionKey, strAlgorithm)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(ret[1])
            decryptedElements[key] = object
        self.elements = decryptedElements
        ret = self.update(decrypt = True, algorithm = altAlgorithm)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
    
    def delElement(self, name, update = True):
        onlyElements = True
        if name in self.elements:
            if name in ['/Filter','/DecodeParm','/FFilter','/FDecodeParm']:
                self.deletedFilters = True
                onlyElements = False
            del(self.elements[name])
            if update:
                ret = self.update(onlyElements = onlyElements)
            return ret
        else:
            return (-1,'Element not found')

    def encode (self) :
        '''
            Encode the decoded stream and update the content of rawStream
        '''
        errorMessage = ''
        if len(self.decodedStream) > 0:
            if self.filter == None:
                return (-1,'Bad /Filter element')
            filterType = self.filter.getType()
            if self.filterParams != None:
                filterParamsType = self.filterParams.getType()
            if filterType == 'name':
                if self.filterParams == None:
                    ret = encodeStream(self.decodedStream, self.filter.getValue(), self.filterParams)
                    if ret[0] == -1:
                        errorMessage = 'Encoding error: '+ret[1]
                        if get_parser_context().force_mode:
                            self.addError(errorMessage)
                            self.encodedStream = ''
                        else:
                            return (-1,errorMessage)
                    else:
                        self.rawStream = ret[1]
                elif filterParamsType == 'dictionary':
                    ret = encodeStream(self.decodedStream, self.filter.getValue(), self.filterParams.getElements())
                    if ret[0] == -1:
                        errorMessage = 'Encoding error: '+ret[1]
                        if get_parser_context().force_mode:
                            self.addError(errorMessage)
                            self.encodedStream = ''
                        else:
                            return (-1,errorMessage)
                    else:
                        self.rawStream = ret[1]        
                else:
                    if get_parser_context().force_mode:
                        errorMessage = 'Filter parameters type is not valid'
                        self.addError(errorMessage)
                        self.encodedStream = ''
                    else:
                        return (-1,'Filter parameters type is not valid')
            elif filterType == 'array':
                self.rawStream = self.decodedStream
                filterElements = list(self.filter.getElements())
                filterElements.reverse()
                if self.filterParams != None and filterParamsType == 'array':
                    paramsArray = self.filterParams.getElements()
                    for j in range(len(paramsArray),len(filterElements)):
                        paramsArray.append(PDFNull('Null'))
                    paramsArray.reverse()
                else:
                    paramsArray = []
                for i in range(len(filterElements)):
                    filter = filterElements[i]
                    if filter == None:
                        if get_parser_context().force_mode:
                            errorMessage = 'Bad /Filter element in PDFArray'
                            self.addError(errorMessage)
                            continue
                        return (-1,'Bad /Filter element in PDFArray')
                    if filter.getType() == 'name':
                        if self.filterParams == None:
                            ret = encodeStream(self.rawStream, filter.getValue(), self.filterParams)
                            if ret[0] == -1:
                                errorMessage = 'Encoding error: '+ret[1]
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                    self.encodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.rawStream = ret[1]
                        elif filterParamsType == 'array':
                            paramsObj = paramsArray[i]
                            if paramsObj == None:
                                if get_parser_context().force_mode:
                                    errorMessage = 'Bad /FilterParms element in PDFArray'
                                    self.addError(errorMessage)
                                    continue
                                return (-1,'Bad /FilterParms element in PDFArray')
                            paramsObjType = paramsObj.getType()
                            if paramsObjType == 'dictionary':
                                paramsDict = paramsObj.getElements()
                            else:
                                paramsDict = {}

                            ret = encodeStream(self.rawStream, filter.getValue(), paramsDict)
                            if ret[0] == -1:
                                errorMessage = 'Encoding error: '+ret[1]
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                    self.encodedStream = ''
                                else:
                                    return (-1,errorMessage)
                            else:
                                self.rawStream = ret[1]    
                        else:
                            if get_parser_context().force_mode:
                                errorMessage = 'One of the filters parameters type is not valid'
                                self.addError(errorMessage)
                                self.encodedStream = ''
                            else:
                                return (-1,'One of the filters parameters type is not valid')
                    else:
                        if get_parser_context().force_mode:
                            errorMessage = 'One of the filters type is not valid'
                            self.addError(errorMessage)
                            self.encodedStream = ''
                        else:
                            return (-1,'One of the filters type is not valid')
            else:
                if get_parser_context().force_mode:
                    errorMessage = 'Filter type is not valid'
                    self.addError(errorMessage)
                    self.encodedStream = ''
                else:
                    return (-1,'Filter type is not valid')
            self.encodedStream = self.rawStream
            if errorMessage != '':
                return (-1,errorMessage)
            else:
                return (0,'')
        else:
            return (-1,'Empty stream')
    
    def encrypt(self, password = None):
        self.encrypted = True
        if password != None:
            self.encryptionKey = password
        ret = self.update()
        return ret
                    
    def getEncryptedValue(self):
        return self.encryptedValue + newLine + 'stream' + newLine + self.rawStream + newLine + 'endstream'

    def getStats(self):
        stats = {}
        stats['Object'] = self.type
        stats['MD5'] = hashlib.md5(self.value).hexdigest()
        stats['SHA1'] = hashlib.sha1(self.value).hexdigest()
        stats['Stream MD5'] = hashlib.md5(self.decodedStream).hexdigest()
        stats['Stream SHA1'] = hashlib.sha1(self.decodedStream).hexdigest()
        stats['Raw Stream MD5'] = hashlib.md5(self.rawStream).hexdigest()
        stats['Raw Stream SHA1'] = hashlib.sha1(self.rawStream).hexdigest()
        if self.isCompressed():
            stats['Compressed in'] = str(self.compressedIn)
        else:
            stats['Compressed in'] = None
        stats['References'] = str(self.references)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        if self.dictType != '':
            stats['Type'] = self.dictType
        else:
            stats['Type'] = None
        if '/Subtype' in self.elements:
            stats['Subtype'] = self.elements['/Subtype'].getValue()
        else:
            stats['Subtype'] = None
        if '/S' in self.elements:
            stats['Action type'] = self.elements['/S'].getValue()
        else:
            stats['Action type'] = None
        stats['Length'] = str(self.size)
        if self.size != len(self.rawStream):
            stats['Real Length'] = str(len(self.rawStream))
        else:
            stats['Real Length'] = None
        if self.isEncodedStream:
            stats['Encoded'] = True
            if self.file != None:
                stats['Stream File'] = self.file
            else:
                stats['Stream File'] = None
            stats['Filters'] = self.filter.getValue()
            if self.filterParams != None:
                stats['Filter Parameters'] = True
            else:
                stats['Filter Parameters'] = False
            if self.decodingError:
                stats['Decoding Errors'] = True
            else:
                stats['Decoding Errors'] = False
        else:
            stats['Encoded'] = False
        if self.containsJScode:
            stats['JSCode'] = True
            if len(self.unescapedBytes) > 0:
                stats['Escaped Bytes'] = True
            else:
                stats['Escaped Bytes'] = False
            if len(self.urlsFound) > 0:
                stats['URLs'] = True
            else:
                stats['URLs'] = False
        else:
            stats['JSCode'] = False
        return stats
    
    def getStream(self):
        '''
            Gets the stream of the object 
            
            @return: The stream of the object (string), this means applying filters or decoding characters
        '''
        return self.decodedStream
    
    def getRawStream(self):
        '''
            Gets the raw value of the stream of the object 
            
            @return: The raw value of the stream (string), this means without applying filters or decoding characters
        '''
        return self.rawStream

    def getRawValue(self):
        if self.isEncoded():
            stream = self.encodedStream
        else:
            stream = self.decodedStream
        return self.rawValue + newLine + 'stream' + newLine + stream + newLine + 'endstream'
    
    def getValue(self):
        return self.value + newLine +'stream' + newLine + self.decodedStream + newLine + 'endstream'
    
    def isEncoded(self):
        '''
            Specifies if the stream is encoded with some type of filter (/Filter) 
            
            @return: A boolean
        '''
        return self.isEncodedStream
    
    def isFaultyDecoding(self):
        '''
            Specifies if there are any errors in the process of decoding the stream 
            
            @return: A boolean
        '''
        return self.decodingError
    
    def replace(self, string1, string2):
        stringFound = False
        # Dictionary
        newElements = {}
        errorMessage = ''
        for key in self.elements:
            if key == '/F' and self.elements[key] != None:
                externalFile = self.elements[key].getValue()
                if externalFile != self.file:
                    self.modifiedRawStream = True
                    self.decodedStream = ''
            if key.find(string1) != -1:
                newKey = key.replace(string1, string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            else:
                newKey = key
            newObject = self.elements[key]
            ret = newObject.replace(string1, string2)
            if ret[0] == -1:
                if ret[1] != 'String not found' or not stringFound:
                    errorMessage = ret[1]
            else:
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            newElements[newKey] = newObject
        # Stream
        if not self.modifiedRawStream:
            oldDecodedStream = self.decodedStream
            if self.decodedStream.find(string1) != -1:
                self.decodedStream = self.decodedStream.replace(string1,string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            if oldDecodedStream != self.decodedStream:
                self.modifiedStream = True
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update()
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret

    def resolveReferences(self):
        errorMessage = ''
        if '/Length' in self.referencesInElements:
            value = self.referencesInElements['/Length'][1]
            self.size = int(value)
            self.cleanStream()
        self.updateNeeded = False
        ret = self.decode()
        if ret[0] == -1:
            errorMessage = ret[1]
        refs = re.findall(r'(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
        if refs != []:
            self.references += refs
            self.references = list(set(self.references))
        if isJavascript(self.decodedStream) or self.referencedJSObject:
            self.containsJScode = True
            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], get_parser_context().manual_analysis)
            if jsErrors != []:
                for jsError in jsErrors:
                    errorMessage = 'Error analysing Javascript: '+jsError
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')

    def setDecodedStream(self, newStream):
        '''
            Sets the decoded value of the stream and updates the object if some modification is needed
            
            @param newStream: The new raw value (string)
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.decodedStream = newStream
        self.modifiedStream = True
        ret = self.update()
        return ret
    
    def setElement(self, name, value, update = True):
        onlyElements = True
        if name in ['/Filter','/DecodeParm','/FFilter','/FDecodeParm']:
            self.newFilters = True
            onlyElements = False
        self.elements[name] = value
        if update:
            ret = self.update(onlyElements = onlyElements)
            return ret
        return (0,'')
    
    def setElements(self, newElements):
        diffElements = []
        oldElements = list(self.elements.keys())
        for oldElement in oldElements:
            if oldElement not in newElements:
                if oldElement in ['/Filter','/FFilter']:
                    self.deletedFilters = True
                    onlyElements = False
                    break
        self.elements = newElements
        if not self.deletedFilters:
            for name in self.elements:
                if name in ['/Filter','/DecodeParm','/FFilter','/FDecodeParm']:
                    self.newFilters = True
                    onlyElements = False
                    break
        ret = self.update()
        return ret

    def setReferencedJSObject(self, value):
        '''
            Modifies the referencedJSObject element

            @param value: The new value (bool)
        '''
        self.referencedJSObject = value
        self.modifiedRawStream = True  # The stream has not been modified but we want to force all the operations again
        ret = self.update()
        return ret

    def setRawStream(self, newStream):
        '''
            Sets the raw value of the stream and updates the object if some modification is needed
            
            @param newStream: The new raw value (string)
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.rawStream = newStream
        self.modifiedRawStream = True
        ret = self.update()
        return ret
    

class PDFObjectStream (PDFStream) :
    def __init__(self, rawDict = '', rawStream = '', elements = None, rawNames = None, compressedObjectsDict = None) :
        elements = {} if elements is None else elements
        rawNames = {} if rawNames is None else rawNames
        compressedObjectsDict = {} if compressedObjectsDict is None else compressedObjectsDict
        self.type = 'stream'
        self.dictType = ''
        self.errors = []
        self.compressedIn = None
        self.encrypted = False
        self.decodedStream = ''
        self.encodedStream = ''
        self.rawStream = rawStream
        self.newRawStream = False
        self.newFilters = False
        self.deletedFilters = False
        self.modifiedStream = False
        self.modifiedRawStream = True
        self.rawValue = rawDict
        self.encryptedValue = rawDict
        self.rawNames = rawNames
        self.value = '' # string
        self.updateNeeded = False
        self.containsJScode = False
        self.referencedJSObject = False
        self.JSCode = []
        self.uriList = []
        self.unescapedBytes = []
        self.urlsFound = []
        self.referencesInElements = {}
        self.references = []
        self.elements = elements
        self.compressedObjectsDict = compressedObjectsDict
        self.indexes = []
        self.firstObjectOffset = 0
        self.numCompressedObjects = 0
        self.extends = None
        self.size = 0
        self.filter = None
        self.filterParams = None
        self.file = None
        self.isEncodedStream = False
        self.decodingError = False
        if self.elements:
            ret = self.update()
            if ret[0] == -1:
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                else:
                    raise Exception(ret[1]) 
        else:
            self.addError('No dictionary in stream object')

    def update(self, modifiedCompressedObjects = False, onlyElements = False, decrypt = False, algorithm = 'RC4'):
        '''
            Updates the object after some modification has occurred
            
            @param modifiedCompressedObjects: A boolean indicating if the compressed objects hav been modified. By default: False.
            @param onlyElements: A boolean indicating if it's only necessary to update the stream dictionary or also the stream itself. By default: False (stream included).
            @param decrypt: A boolean indicating if a decryption has been performed. By default: False.
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        self.value = '<< '
        self.rawValue = '<< '
        self.encryptedValue = '<< '
        keys = list(self.elements.keys())
        values = list(self.elements.values())
        if not onlyElements:
            self.errors = []
            self.references = []
            self.JSCode = []
            self.unescapedBytes = []
            self.urlsFound = []
            self.containsJScode = False
            self.decodingError = False
            
        # Dictionary
        if '/First' in self.elements and self.elements['/First'] != None:
            self.firstObjectOffset = self.elements['/First'].getRawValue()
        else:
            if get_parser_context().force_mode:
                self.addError('No /First element in the object stream or it\'s None')
            else:
                return (-1,'No /First element in the object stream or it\'s None')
        if '/N' in self.elements and self.elements['/N'] != None:
            self.numCompressedObjects = self.elements['/N'].getRawValue()
        else:
            if get_parser_context().force_mode:
                self.addError('No /N element in the object stream or it\'s None')
            else:
                return (-1,'No /N element in the object stream or it\'s None')

        if '/Extends' in self.elements and self.elements['/Extends'] != None:
            self.extends = self.elements['/Extends'].getValue()

        if '/Length' in self.elements:
            length = self.elements['/Length']
            if length != None:
                if length.getType() == 'integer':
                    self.size = length.getRawValue()
                elif length.getType() == 'reference':
                    self.updateNeeded = True
                    self.referencesInElements['/Length'] = [length.getId(),'']
                else:
                    if get_parser_context().force_mode:
                        self.addError('No permitted type for /Length element')
                    else:
                        return (-1,'No permitted type for /Length element')
            else:
                if get_parser_context().force_mode:
                    self.addError('None /Length element')
                else:
                    return (-1,'None /Length element')
        else:
            if get_parser_context().force_mode:
                self.addError('Missing /Length in stream object')
            else:
                return (-1,'Missing /Length in stream object')
            
        if '/F' in self.elements:
            self.file = self.elements['/F'].getValue()
            if os.path.exists(self.file):
                self.rawStream = open(self.file,'rb').read()
            else:
                if get_parser_context().force_mode:
                    self.addError('File "'+self.file+'" does not exist (/F)')
                    self.rawStream = ''
                else:
                    return (-1,'File "'+self.file+'" does not exist (/F)')            
            
        if '/Filter' in self.elements:
            self.filter = self.elements['/Filter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        elif '/FFilter' in self.elements:
            self.filter = self.elements['/FFilter']
            if self.newFilters or self.modifiedStream:
                self.encodedStream = ''
                self.rawStream = ''
            elif not self.encrypted:
                self.encodedStream = self.rawStream
            self.isEncodedStream = True
        else:
            self.encodedStream = ''
            if self.deletedFilters or self.modifiedStream:
                self.rawStream = self.decodedStream
            elif not self.encrypted:
                self.decodedStream = self.rawStream
            self.isEncodedStream = False
        if self.isEncodedStream:
            if '/DecodeParms' in self.elements:
                self.filterParams = self.elements['/DecodeParms']
            elif '/FDecodeParms' in self.elements:
                self.filterParams = self.elements['/FDecodeParms']
            elif '/DP' in self.elements:
                self.filterParams = self.elements['/DP']
            else:
                self.filterParams = None
                
        for i in range(len(keys)):
            valueElement = values[i]
            if valueElement == None:
                if get_parser_context().force_mode:
                    errorMessage = 'Stream dictionary has a None value'
                    self.addError(errorMessage)
                    valueElement = PDFString('')
                else:
                    return (-1,'Stream dictionary has a None value')
            v = valueElement.getValue()
            type = valueElement.getType()
            if type == 'reference':
                if v not in self.references: 
                    self.references.append(v)
            elif type == 'dictionary' or type == 'array':
                self.references = list(set(self.references + valueElement.getReferences()))
            if valueElement.containsJS():
                self.containsJScode = True
                self.JSCode = list(set(self.JSCode + valueElement.getJSCode()))
                self.unescapedBytes = list(set(self.unescapedBytes + valueElement.getUnescapedBytes()))
                self.urlsFound = list(set(self.urlsFound + valueElement.getURLs()))
            if valueElement.isFaulty():
                errorMessage = 'Child element is faulty'
                self.addError(errorMessage)
            if keys[i] in self.rawNames:
                rawName = self.rawNames[keys[i]]
                rawValue = rawName.getRawValue()
            else:
                rawValue = keys[i]
                self.rawNames[keys[i]] = PDFName(keys[i][1:])
            if type in ['string','hexstring','array','dictionary'] and self.encrypted and not decrypt:
                ret = valueElement.encrypt(self.encryptionKey)
                if ret[0] == -1:
                    errorMessage = ret[1]+' in child element'
                    self.addError(errorMessage)
            self.encryptedValue += rawValue + ' ' + str(valueElement.getEncryptedValue()) + newLine
            self.rawValue += rawValue + ' ' + str(valueElement.getRawValue()) + newLine
            self.value += keys[i] + ' ' + v + newLine
        self.encryptedValue = self.encryptedValue[:-1] + ' >>'
        self.rawValue = self.rawValue[:-1] + ' >>'
        self.value = self.value[:-1] + ' >>'
        
        if not onlyElements:
            # Stream
            if self.deletedFilters or self.newFilters or self.modifiedStream or self.modifiedRawStream or modifiedCompressedObjects or self.encrypted:
                if self.deletedFilters:
                    if self.encrypted:
                        try:
                            self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                        except:
                            errorMessage = 'Error encrypting stream with RC4'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        self.size = len(self.rawStream)
                    else:
                        self.size = len(self.decodedStream)
                elif self.newFilters:
                    ret = self.encode()
                    if ret[0] != -1:
                        if self.encrypted:
                            try:
                                self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            self.size = len(self.encodedStream)
                else:
                    if self.modifiedStream or self.modifiedRawStream:
                        if self.modifiedStream:
                            if self.isEncodedStream:
                                ret = self.encode()
                                if ret[0] != -1:
                                    if self.encrypted:
                                        try:
                                            self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                                        except:
                                            errorMessage = 'Error encrypting stream with RC4'
                                            if get_parser_context().force_mode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                        self.size = len(self.rawStream)
                                    else:
                                        self.size = len(self.encodedStream)
                            else:
                                if self.encrypted:
                                    try:
                                        self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                                    except:
                                        errorMessage = 'Error encrypting stream with RC4'
                                        if get_parser_context().force_mode:
                                            self.addError(errorMessage)
                                        else:
                                            return (-1,errorMessage)
                                    self.size = len(self.rawStream)
                                else:
                                    self.size = len(self.decodedStream)
                        elif self.modifiedRawStream:
                            if len(self.rawStream) > 0:
                                self.cleanStream()
                            if not self.updateNeeded:
                                if self.encrypted:
                                    if self.isEncodedStream:
                                        if decrypt:
                                            try:
                                                if algorithm == 'RC4':
                                                    self.encodedStream = RC4(self.rawStream,self.encryptionKey)
                                                elif algorithm == 'AES':
                                                    ret = AES.decryptData(self.rawStream,self.encryptionKey)
                                                    if ret[0] != -1:
                                                        self.encodedStream = ret[1]
                                                    else:
                                                        errorMessage = 'AES decryption error: '+ret[1]
                                                        if get_parser_context().force_mode:
                                                            self.addError(errorMessage)
                                                        else:
                                                            return (-1,errorMessage)
                                            except:
                                                errorMessage = 'Error decrypting stream with '+str(algorithm)
                                                if get_parser_context().force_mode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1,errorMessage)
                                        else:
                                            self.encodedStream = self.rawStream
                                            try:
                                                self.rawStream = RC4(self.rawStream,self.encryptionKey)
                                            except:
                                                errorMessage = 'Error encrypting stream with RC4'
                                                if get_parser_context().force_mode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1,errorMessage)
                                        self.decode()
                                    else:
                                        try:
                                            self.decodedStream = RC4(self.rawStream,self.encryptionKey)
                                        except:
                                            errorMessage = 'Error encrypting stream with RC4'
                                            if get_parser_context().force_mode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                else:
                                    if self.isEncodedStream:
                                        self.decode()
                                self.size = len(self.rawStream)
                        offsetsSection = self.decodedStream[:self.firstObjectOffset]
                        objectsSection = self.decodedStream[self.firstObjectOffset:]
                        numbers = re.findall(r'\d{1,10}', offsetsSection)
                        if numbers != [] and len(numbers) % 2 == 0:
                            for i in range(0,len(numbers),2):
                                id = int(numbers[i])
                                offset = int(numbers[i+1])
                                ret = _get_pdf_parser().readObject(objectsSection[offset:])
                                if ret[0] == -1:
                                    if get_parser_context().force_mode:
                                        object = None
                                        self.addError(ret[1])
                                    else:
                                        return ret
                                else:
                                    object = ret[1]
                                self.compressedObjectsDict[id] = [offset,object]
                                self.indexes.append(id)
                        else:
                            if get_parser_context().force_mode:
                                self.addError('Missing offsets in object stream')
                            else:
                                return (-1,'Missing offsets in object stream')
                    elif modifiedCompressedObjects:
                        tmpStreamObjects = ''
                        tmpStreamObjectsInfo = ''
                        for objectId in self.indexes:
                            offset = len(tmpStreamObjects)
                            tmpStreamObjectsInfo += str(objectId)+' '+str(offset)+' '
                            object = self.compressedObjectsDict[objectId][1]
                            tmpStreamObjects += object.toFile()
                            self.compressedObjectsDict[objectId] = [offset,object]
                        self.decodedStream = tmpStreamObjectsInfo + tmpStreamObjects
                        self.firstObjectOffset = len(tmpStreamObjectsInfo)
                        self.setElementValue('/First',str(self.firstObjectOffset))
                        self.numCompressedObjects = len(self.compressedObjectsDict)
                        self.setElementValue('/N',str(self.numCompressedObjects))
                        if self.isEncodedStream:
                            self.encode()
                            self.size = len(self.encodedStream)
                        else:
                            self.size = len(self.decodedStream)
                    else:
                        if not decrypt:
                            try:
                                if self.isEncodedStream:
                                    self.rawStream = RC4(self.encodedStream,self.encryptionKey)
                                else:
                                    self.rawStream = RC4(self.decodedStream,self.encryptionKey)
                            except:
                                errorMessage = 'Error encrypting stream with RC4'
                                if get_parser_context().force_mode:
                                    self.addError(errorMessage)
                                else:
                                    return (-1,errorMessage)
                            self.size = len(self.rawStream)
                        else:
                            if self.isEncodedStream:
                                try:
                                    if algorithm == 'RC4':
                                        self.encodedStream = RC4(self.rawStream,self.encryptionKey)
                                    elif algorithm == 'AES':
                                        ret = AES.decryptData(self.rawStream,self.encryptionKey)
                                        if ret[0] != -1:
                                            self.encodedStream = ret[1]
                                        else:
                                            errorMessage = 'AES decryption error: '+ret[1]
                                            if get_parser_context().force_mode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                except:
                                    errorMessage = 'Error decrypting stream with '+str(algorithm)                    
                                    if get_parser_context().force_mode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                                self.decode()
                            else:
                                try:
                                    if algorithm == 'RC4':
                                        self.decodedStream = RC4(self.rawStream,self.encryptionKey)
                                    elif algorithm == 'AES':
                                        ret = AES.decryptData(self.rawStream,self.encryptionKey)
                                        if ret[0] != -1:
                                            self.decodedStream = ret[1]
                                        else:
                                            errorMessage = 'AES decryption error: '+ret[1]
                                            if get_parser_context().force_mode:
                                                self.addError(errorMessage)
                                            else:
                                                return (-1,errorMessage)
                                except:
                                    errorMessage = 'Error decrypting stream with '+str(algorithm)                                
                                    if get_parser_context().force_mode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                            offsetsSection = self.decodedStream[:self.firstObjectOffset]
                            objectsSection = self.decodedStream[self.firstObjectOffset:]
                            numbers = re.findall(r'\d{1,10}', offsetsSection)
                            if numbers != [] and len(numbers) % 2 == 0:
                                for i in range(0,len(numbers),2):
                                    id = int(numbers[i])
                                    offset = int(numbers[i+1])
                                    ret = _get_pdf_parser().readObject(objectsSection[offset:])
                                    if ret[0] == -1:
                                        if get_parser_context().force_mode:
                                            object = None
                                            self.addError(ret[1])
                                        else:
                                            return ret
                                    else:
                                        object = ret[1]
                                    self.compressedObjectsDict[id] = [offset,object]
                                    self.indexes.append(id)
                            else:
                                if get_parser_context().force_mode:
                                    self.addError('Missing offsets in object stream')
                                else:
                                    return (-1,'Missing offsets in object stream')
                    if not self.isFaultyDecoding():
                        refs = re.findall(r'(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                        if refs != []:
                            self.references += refs
                            self.references = list(set(self.references))
                        if isJavascript(self.decodedStream) or self.referencedJSObject:
                            self.containsJScode = True
                            self.JSCode, self.unescapedBytes, self.urlsFound, jsErrors, jsContexts['global'] = analyseJS(self.decodedStream, jsContexts['global'], get_parser_context().manual_analysis)
                            if jsErrors != []:
                                for jsError in jsErrors:
                                    errorMessage = 'Error analysing Javascript: '+jsError
                                    if get_parser_context().force_mode:
                                        self.addError(errorMessage)
                                    else:
                                        return (-1,errorMessage)
                if not self.modifiedRawStream:
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
                    errors = self.errors
                    try:
                        self.setElement('/Length',PDFNum(str(self.size)))
                        self.errors += errors
                    except:
                        errorMessage = 'Error creating PDFNum'
                        if get_parser_context().force_mode:
                            self.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                else:
                    self.modifiedRawStream = False
                    self.modifiedStream = False
                    self.newFilters = False
                    self.deletedFilters = False
        if self.errors != []:
            return (-1,self.errors[-1])
        else:
            return (0,'')

    def getCompressedObjects(self):
        '''
            Gets the information of the compressed objects: offset and content. 
            
            @return: A dictionary with this information: {id: [offset,PDFObject]}
        '''
        return self.compressedObjectsDict

    def getObjectIndex(self, id):
        '''
            Gets the index of the object in the dictionary of compressed objects 
            
            @param id: The object id
            @return: The index (int) or None if the object hasn't been found
        '''
        if id not in self.indexes:
            return None
        else:
            return self.indexes.index(id)
                    
    def replace(self, string1, string2):
        stringFound = False
        # Dictionary
        newElements = {}
        errorMessage = ''
        for key in self.elements:
            if key == '/F' and self.elements[key] != None:
                externalFile = self.elements[key].getValue()
                if externalFile != self.file:
                    self.modifiedRawStream = True
                    self.decodedStream = ''
            if key.find(string1) != -1:
                newKey = key.replace(string1, string2)
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            else:
                newKey = key
            newObject = self.elements[key]
            ret = newObject.replace(string1, string2)
            if ret[0] == -1:
                if ret[1] != 'String not found' or not stringFound:
                    errorMessage = ret[1]
            else:
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            newElements[newKey] = newObject
        # Stream
        if not self.modifiedRawStream:
            if self.decodedStream.find(string1) != -1:
                modifiedObjects = True
                stringFound = True
                if errorMessage == 'String not found':
                    errorMessage = ''
            for compressedObjectId in self.compressedObjectsDict:
                object = self.compressedObjectsDict[compressedObjectId][1]
                object.replace(string1,string2)
                self.compressedObjectsDict[compressedObjectId][1] = object
        if not stringFound:
            return (-1,'String not found')
        self.elements = newElements
        ret = self.update(modifiedObjects)
        if ret[0] == 0 and errorMessage != '':
            return (-1,errorMessage)
        return ret
                    
    def resolveReferences(self):
        errorMessage = ''
        if '/Length' in self.referencesInElements:
            value = self.referencesInElements['/Length'][1]
            self.size = int(value)
            self.cleanStream()
        self.updateNeeded = False
        if self.isEncodedStream:
            ret = self.decode()
            if ret[0] == -1:
                return ret
            if not self.isFaultyDecoding():
                refs = re.findall(r'(\d{1,5}\s{1,3}\d{1,5}\s{1,3}R)', self.decodedStream)
                if refs != []:
                    self.references += refs
                    self.references = list(set(self.references))
                # Extracting the compressed objects
                offsetsSection = self.decodedStream[:self.firstObjectOffset]
                objectsSection = self.decodedStream[self.firstObjectOffset:]
                numbers = re.findall(r'\d{1,10}', offsetsSection)
                if numbers != [] and len(numbers) % 2 == 0:
                    for i in range(0,len(numbers),2):
                        id = numbers[i]
                        offset = numbers[i+1]
                        ret = _get_pdf_parser().readObject(objectsSection[offset:])
                        if ret[0] == -1:
                            if get_parser_context().force_mode:
                                object = None
                                self.addError(ret[1])
                            else:
                                return ret
                        else:
                            object = ret[1]
                        self.compressedObjectsDict[numbers[i]] = [offset,object]
                else:
                    errorMessage = 'Missing offsets in object stream'
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
        if errorMessage != '':
            return (-1,errorMessage)
        else:
            return (0,'')
    
    def setCompressedObjectId(self,id):
        '''
            Sets the compressedIn attribute of the compressed object defined by its id
            
            @param id: The object id
            @return: A tuple (status,statusContent), where statusContent is empty in case status = 0 or an error message in case status = -1
        '''
        for compressedId in self.compressedObjectsDict:
            if self.compressedObjectsDict[compressedId] != None:
                object = self.compressedObjectsDict[compressedId][1]
                object.setCompressedIn(id)
                self.compressedObjectsDict[compressedId][1] = object
            else:
                return (-1,'Compressed object corrupted')
        return (0,'')


class PDFIndirectObject :
    def __init__(self) :
        self.referenced = [] # int[]
        self.object = None # PDFObject
        self.offset = 0 # int
        self.generationNumber = 0 # int
        self.id = None # int
        self.size = 0 # int
        
    def contains(self, string):
        return self.object.contains(string)

    def getErrors(self):
        return self.object.getErrors()
    
    def getGenerationNumber(self):
        return self.generationNumber
    
    def getId(self):
        return self.id
    
    def getObject(self):
        return self.object

    def getOffset(self):
        return self.offset
        
    def getReferences(self):
        return self.object.getReferences()
    
    def getSize(self):
        return self.size

    def getStats(self):
        stats = self.object.getStats()
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        return stats

    def isFaulty(self):
        return self.object.isFaulty()
    
    def setGenerationNumber(self, generationNumber):
        self.generationNumber = generationNumber
        
    def setId(self, id):
        self.id = id
    
    def setObject(self, object):
        self.object = object
    
    def setOffset(self, offset):
        self.offset = offset

    def setSize(self, newSize):
        self.size = newSize    

    def toFile(self):
        rawValue = self.object.toFile()
        output = str(self.id)+' '+str(self.generationNumber)+' obj' + newLine + rawValue + newLine + 'endobj' + newLine*2
        self.size = len(output)
        return output
