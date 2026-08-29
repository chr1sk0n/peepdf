"""PDF Parser implementation."""

import aes as AES
import hashlib
import os
import re
import struct
import sys

from js_analysis import analyseJS, isJavascript
from parser_context import ParserContext, get_parser_context, set_parser_context
from pdf_constants import (
    MAL_ALL,
    MAL_BAD_HEAD,
    MAL_EOBJ,
    MAL_ESTREAM,
    MAL_HEAD,
    MAL_XREF,
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
from pdf_objects import (
    PDFArray,
    PDFBool,
    PDFDictionary,
    PDFHexString,
    PDFIndirectObject,
    PDFName,
    PDFNull,
    PDFNum,
    PDFObject,
    PDFObjectStream,
    PDFReference,
    PDFStream,
    PDFString,
)
from pdf_structure import (
    PDFBody,
    PDFCrossRefEntry,
    PDFCrossRefSection,
    PDFCrossRefSubSection,
    PDFFile,
    PDFTrailer,
)
from pdf_crypto import (
    RC4,
    computeEncryptionKey,
    computeObjectKey,
    computeOwnerPass,
    computeUserPass,
    isOwnerPass,
    isUserPass,
)
from pdf_filters import decodeStream, encodeStream
from pdf_utils import (
    encodeName,
    encodeString,
    escapeString,
    numToHex,
    numToString,
    unescapeString,
)

class PDFParser :
    def __init__(self) :
        self.commentChar = '%'
        self.comments = []
        self.delimiters = [('<<','>>','dictionary'),('(',')','string'),('<','>','hexadecimal'),('[',']','array'),('{','}',''),('/','','name'),('%','','comment')]
        self.fileParts = []
        self.charCounter = 0    
    
    def parse(self, fileName, forceMode=False, looseMode=False, manualAnalysis=False):
        with set_parser_context(forceMode, manualAnalysis):
            return self._parse(fileName, forceMode, looseMode, manualAnalysis)

    def _parse(self, fileName, forceMode=False, looseMode=False, manualAnalysis=False):
        '''
            Main method to parse a PDF document
            @param fileName The name of the file to be parsed
            @param forceMode Boolean to specify if ignore errors or not. Default value: False.
            @param looseMode Boolean to set the loose mode when parsing objects. Default value: False.
            @return A PDFFile instance
        '''
        isFirstBody = True
        linearizedFound = False
        errorMessage = ''
        versionLine = ''
        binaryLine = ''
        headerOffset = 0
        garbageHeader = ''
        self.pdfFile = PDFFile()
        self.pdfFile.setPath(fileName)
        self.pdfFile.setFileName(os.path.basename(fileName))
        
        # Reading the file header
        with open(fileName, 'r', encoding='latin-1', newline='') as file:
            for line in file:
                if versionLine == '':
                    pdfHeaderIndex = line.find('%PDF-')
                    psHeaderIndex = line.find('%!PS-Adobe-')
                    if pdfHeaderIndex != -1 or psHeaderIndex != -1:
                        index = line.find('\r')
                        if index != -1 and index+1 < len(line) and line[index+1] != '\n':
                            index += 1
                            versionLine = line[:index]
                            binaryLine = line[index:]
                            break
                        else:
                            versionLine = line
                        if pdfHeaderIndex != -1:
                            headerOffset += pdfHeaderIndex
                        else:
                            headerOffset += psHeaderIndex
                        self.pdfFile.setHeaderOffset(headerOffset)
                    else:
                        garbageHeader += line
                else:
                    binaryLine = line
                    break
                headerOffset += len(line)
        
        # Getting the specification version
        versionLine = versionLine.replace('\r','')
        versionLine = versionLine.replace('\n','')
        matchVersion = re.findall(r'%(PDF-|!PS-Adobe-\d{1,2}\.\d{1,2}\sPDF-)(\d{1,2}\.\d{1,2})',versionLine)
        if matchVersion == []:
            if forceMode:
                self.pdfFile.setVersion(versionLine)
                self.pdfFile.addError('Bad PDF header')
                errorMessage = 'Bad PDF header'
            else:
                sys.exit('Error: Bad PDF header!! (' + versionLine + ')')
        else:
            self.pdfFile.setVersion(matchVersion[0][1])
        if garbageHeader != '':
            self.pdfFile.setGarbageHeader(garbageHeader)
            
        # Getting the end of line
        if len(binaryLine) > 3:
            if binaryLine[-2:] == '\r\n':
                self.pdfFile.setEndLine('\r\n')
            else:
                if binaryLine[-1] == '\r':
                    self.pdfFile.setEndLine('\r')
                elif binaryLine[-1] == '\n':
                    self.pdfFile.setEndLine('\n')
                else:
                    self.pdfFile.setEndLine('\n')
        
            # Does it contain binary characters??
            if binaryLine[0] == '%' and ord(binaryLine[1]) >= 128 and ord(binaryLine[2]) >= 128 and ord(binaryLine[3]) >= 128 and ord(binaryLine[4]) >= 128:
                self.pdfFile.binary = True
                self.pdfFile.binaryChars = binaryLine[1:5]
            else:
                self.pdfFile.binary = False
            
        # Reading the rest of the file
        with open(fileName, 'rb') as f:
            rawFileContent = f.read()
        fileContent = rawFileContent.decode('latin-1')
        self.pdfFile.setSize(len(rawFileContent))
        self.pdfFile.setMD5(hashlib.md5(rawFileContent).hexdigest())
        self.pdfFile.setSHA1(hashlib.sha1(rawFileContent).hexdigest())
        self.pdfFile.setSHA256(hashlib.sha256(rawFileContent).hexdigest())
        
        # Getting the number of updates in the file
        while fileContent.find('%%EOF') != -1:
            self.readUntilSymbol(fileContent, '%%EOF')
            self.readUntilEndOfLine(fileContent)
            self.fileParts.append(fileContent[:self.charCounter])
            fileContent = fileContent[self.charCounter:]
            self.charCounter = 0
        else:
            if self.fileParts == []:
                errorMessage = '%%EOF not found'
                if forceMode:
                    self.pdfFile.addError(errorMessage)
                    self.fileParts.append(fileContent)
                else:
                    sys.exit(errorMessage)
        self.pdfFile.setUpdates(len(self.fileParts) - 1)
        
        # Getting the body, cross reference table and trailer of each part of the file
        for i in range(len(self.fileParts)):
            bodyOffset = 0
            xrefOffset = 0
            trailerOffset = 0
            eofOffset = 0
            xrefObject = None
            xrefContent = None
            xrefSection = None
            xrefStreamSection = None
            xrefFound = False
            streamTrailer = None
            trailer = None
            trailerFound = False
            pdfIndirectObject = None
            if not self.pdfFile.isEncrypted():
                encryptDict = None
                encryptDictId = None
            if self.pdfFile.getFileId() == '':
                fileId = None
            content = self.fileParts[i]
            if i == 0:
                bodyOffset = 0
            else:
                bodyOffset = len(self.fileParts[i-1])
                
            # Getting the content for each section
            bodyContent,xrefContent,trailerContent = self.parsePDFSections(content,forceMode,looseMode)
            if xrefContent != None:    
                xrefOffset = bodyOffset + len(bodyContent)
                trailerOffset = xrefOffset + len(xrefContent)
                bodyContent = bodyContent.strip('\r\n')
                xrefContent = xrefContent.strip('\r\n')
                trailerContent = trailerContent.strip('\r\n')
                trailerFound = True
                xrefFound = True
            else:
                if trailerContent != None:
                    xrefOffset = -1
                    trailerOffset = bodyOffset + len(bodyContent)
                    bodyContent = bodyContent.strip('\r\n')
                    trailerContent = trailerContent.strip('\r\n')    
                else:
                    errorMessage = 'PDF sections not found'
                    if forceMode:
                        self.pdfFile.addError(errorMessage)
                    else:
                        sys.exit('Error: '+errorMessage+'!!')

                    
            # Converting the body content in PDFObjects
            body = PDFBody()
            rawIndirectObjects = self.getIndirectObjects(bodyContent, looseMode)
            if rawIndirectObjects != []:
                for j in range(len(rawIndirectObjects)):
                    relativeOffset = 0
                    auxContent = str(bodyContent)
                    rawObject = rawIndirectObjects[j][0]
                    objectHeader = rawIndirectObjects[j][1]
                    while True:
                        index = auxContent.find(objectHeader)
                        if index == -1:
                            relativeOffset = index
                            break
                        relativeOffset += index
                        checkHeader = bodyContent[relativeOffset-1:relativeOffset+len(objectHeader)]
                        if not re.match(r'\d{1,10}'+objectHeader,checkHeader):
                            break
                        else:
                            auxContent = auxContent[index+len(objectHeader):]
                            relativeOffset += len(objectHeader)
                    ret = self.createPDFIndirectObject(rawObject, forceMode, looseMode)
                    if ret[0] != -1:
                        pdfIndirectObject = ret[1]
                        if pdfIndirectObject != None:
                            if relativeOffset == -1:
                                pdfIndirectObject.setOffset(relativeOffset)
                            else:
                                pdfIndirectObject.setOffset(bodyOffset + relativeOffset)
                            ret = body.registerObject(pdfIndirectObject)
                            if ret[0] == -1:
                                self.pdfFile.addError(ret[1])
                            type = ret[1]
                            pdfObject = pdfIndirectObject.getObject()
                            if pdfObject != None:
                                objectType = pdfObject.getType()
                                if objectType == 'dictionary':
                                    if isFirstBody and not linearizedFound:
                                        if pdfObject.hasElement('/Linearized'):
                                            self.pdfFile.setLinearized(True)
                                            linearizedFound = True
                                elif objectType == 'stream' and type == '/XRef':
                                    xrefObject = pdfIndirectObject
                                    ret = self.createPDFCrossRefSectionFromStream(pdfIndirectObject)
                                    if ret[0] != -1:
                                        xrefStreamSection = ret[1]    
                            else:
                                if not forceMode:
                                    sys.exit('Error: An error has occurred while parsing an indirect object!!')
                                else:
                                    self.pdfFile.addError('Object is None')
                        else:
                            if not forceMode:
                                sys.exit('Error: Bad indirect object!!')
                            else:
                                self.pdfFile.addError('Indirect object is None')
                    else:
                        if not forceMode:
                            sys.exit('Error: An error has occurred while parsing an indirect object!!')
                        else:
                            self.pdfFile.addError('Error parsing object: '+str(objectHeader)+' ('+str(ret[1])+')')
            else:
                self.pdfFile.addError('No indirect objects found in the body')
            if pdfIndirectObject != None:
                body.setNextOffset(pdfIndirectObject.getOffset())
            ret = body.updateObjects()
            if ret[0] == -1:
                self.pdfFile.addError(ret[1])
            self.pdfFile.addBody(body)
            self.pdfFile.addNumObjects(body.getNumObjects())
            self.pdfFile.addNumStreams(body.getNumStreams())
            self.pdfFile.addNumURIs(body.getNumURIs())
            self.pdfFile.addNumEncodedStreams(body.getNumEncodedStreams())
            self.pdfFile.addNumDecodingErrors(body.getNumDecodingErrors())
            isFirstBody = False
            
            # Converting the cross reference table content in PDFObjects
            if xrefContent != None:
                ret = self.createPDFCrossRefSection(xrefContent,xrefOffset)
                if ret[0] != -1:
                    xrefSection = ret[1]
            self.pdfFile.addCrossRefTableSection([xrefSection, xrefStreamSection])
            
            # Converting the trailer content in PDFObjects
            if body.containsXrefStreams():
                ret = self.createPDFTrailerFromStream(xrefObject,trailerContent)
                if ret[0] != -1:
                    streamTrailer = ret[1]
                ret = self.createPDFTrailer(trailerContent, trailerOffset, streamPresent = True)
                if ret[0] != -1:
                    trailer = ret[1]
                if streamTrailer != None and not self.pdfFile.isEncrypted():
                    encryptDict = streamTrailer.getDictEntry('/Encrypt')
                    if encryptDict != None:
                        self.pdfFile.setEncrypted(True)
                    elif trailer != None:
                        encryptDict = trailer.getDictEntry('/Encrypt')
                        if encryptDict != None:
                            self.pdfFile.setEncrypted(True)
                    if trailer != None:
                        fileId = trailer.getDictEntry('/ID')
                    if fileId == None:
                        fileId = streamTrailer.getDictEntry('/ID')
            else:
                ret = self.createPDFTrailer(trailerContent, trailerOffset)
                if ret[0] != -1 and not self.pdfFile.isEncrypted():
                    trailer = ret[1]
                    encryptDict = trailer.getDictEntry('/Encrypt')
                    if encryptDict != None:
                        self.pdfFile.setEncrypted(True)
                    fileId = trailer.getDictEntry('/ID')
            if self.pdfFile.getEncryptDict() == None and encryptDict != None:
                objectType = encryptDict.getType()
                if objectType == 'reference':
                    encryptDictId = encryptDict.getId()
                    encryptObject = self.pdfFile.getObject(encryptDictId,i)
                    if encryptObject != None:
                        objectType = encryptObject.getType()
                        encryptDict = encryptObject
                    else:
                        if i == self.pdfFile.updates:
                            self.pdfFile.addError('/Encrypt dictionary not found')
                if objectType == 'dictionary':
                    self.pdfFile.setEncryptDict([encryptDictId,encryptDict.getElements()])

            if fileId != None and self.pdfFile.getFileId() == '':
                objectType = fileId.getType()
                if objectType == 'array':
                    fileIdElements = fileId.getElements()
                    if fileIdElements != None and fileIdElements != []:
                        if fileIdElements[0] != None:
                            fileId = fileIdElements[0].getValue()
                            self.pdfFile.setFileId(fileId)
                        elif fileIdElements[1] != None:
                            fileId = fileIdElements[1].getValue()
                            self.pdfFile.setFileId(fileId)
            self.pdfFile.addTrailer([trailer, streamTrailer])
        if self.pdfFile.isEncrypted() and self.pdfFile.getEncryptDict() != None:
            ret = self.pdfFile.decrypt()
            if ret[0] == -1:
                self.pdfFile.addError(ret[1])
        return (0,self.pdfFile)

    def parsePDFSections(self, content, forceMode = False, looseMode = False):
        '''
            Method to parse the different sections of a version of a PDF document.
            @param content The raw content of the version of the PDF document.
            @param forceMode Boolean to specify if ignore errors or not. Default value: False.
            @param looseMode Boolean to set the loose mode when parsing objects. Default value: False.
            @return An array with the different sections found: body, trailer and cross reference table
        '''
        threeSections = False
        bodyContent = None
        xrefContent = None
        trailerContent = None
        
        indexTrailer = content.find('trailer')
        if indexTrailer != -1:
            restContent = content[:indexTrailer]
            auxTrailer = content[indexTrailer:]
            indexEOF = auxTrailer.find('%%EOF')
            if indexEOF == -1:
                trailerContent = auxTrailer
            else:
                trailerContent = auxTrailer[:indexEOF+5]
            indexXref = restContent.find('xref')
            if indexXref != -1:
                bodyContent = restContent[:indexXref]
                xrefContent = restContent[indexXref:]
            else:
                bodyContent = restContent
                if forceMode:
                    self.pdfFile.addError('Xref section not found')
            return [bodyContent,xrefContent,trailerContent]                
                
        indexTrailer = content.find('startxref')
        if indexTrailer != -1:
            restContent = content[:indexTrailer]
            auxTrailer = content[indexTrailer:]
            indexEOF = auxTrailer.find('%%EOF')
            if indexEOF == -1:
                trailerContent = auxTrailer
            else:
                trailerContent = auxTrailer[:indexEOF+5]
            bodyContent = restContent
            return [bodyContent,xrefContent,trailerContent]
        
        return [content,xrefContent,trailerContent]
    
    def createPDFIndirectObject (self, rawIndirectObject, forceMode = False, looseMode = False) :
        '''
            Create a PDFIndirectObject instance from the raw content of the PDF file
            @param rawIndirectObject string with the raw content of the PDF body.
            @param forceMode specifies if the parsing process should ignore errors or not (boolean).
            @param looseMode specifies if the parsing process should search for the endobj tag or not (boolean).
            @return A tuple (status,statusContent), where statusContent is the PDFIndirectObject in case status = 0 or an error in case status = -1
        '''
        try:
            self.charCounter = 0
            pdfIndirectObject = PDFIndirectObject()
            ret,id = self.readUntilNotRegularChar(rawIndirectObject)
            pdfIndirectObject.setId(int(id))
            ret,genNum = self.readUntilNotRegularChar(rawIndirectObject)
            pdfIndirectObject.setGenerationNumber(int(genNum))
            ret = self.readSymbol(rawIndirectObject, 'obj')
            if ret[0] == -1:
                return ret
            rawObject = rawIndirectObject[self.charCounter:]
            ret = self.readObject(rawObject, forceMode = forceMode, looseMode = looseMode)
            if ret[0] == -1:
                return ret
            object = ret[1]
            pdfIndirectObject.setObject(object)
            ret = self.readSymbol(rawIndirectObject, 'endobj', False)
            pdfIndirectObject.setSize(self.charCounter)
        except:
            errorMessage = 'Unspecified parsing error'
            self.pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        self.pdfFile.setMaxObjectId(id)
        return (0,pdfIndirectObject)

    def createPDFArray(self, rawContent):
        '''
            Create a PDFArray instance from the raw content of the PDF file
            @param rawContent string with the raw content of the PDF body.
            @return A tuple (status,statusContent), where statusContent is the PDFArray in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = []
        ret = self.readObject(rawContent)
        if ret[0] == -1:
            if ret[1] != 'Empty content reading object':
                if get_parser_context().force_mode:
                    self.pdfFile.addError(ret[1])
                    pdfObject = None
                else:
                    return ret
            else:
                pdfObject = None
        else:
            pdfObject = ret[1]
        while pdfObject != None:
            elements.append(pdfObject)
            ret = self.readObject(rawContent[self.charCounter:])
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if get_parser_context().force_mode:
                        self.pdfFile.addError(ret[1])
                        pdfObject = None
                    else:
                        return ret
                else:
                    pdfObject = None
            else:
                pdfObject = ret[1]
        try:
            pdfArray = PDFArray(rawContent, elements)
        except Exception as e:
            errorMessage = 'Error creating PDFArray'
            if e.message != '':
                errorMessage += ': '+e.message
            return (-1, errorMessage)
        self.charCounter = realCounter
        return (0,pdfArray)
        
    def createPDFDictionary(self, rawContent):
        '''
            Create a PDFDictionary instance from the raw content of the PDF file
            @param rawContent string with the raw content of the PDF body.
            @return A tuple (status,statusContent), where statusContent is the PDFDictionary in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = {}
        rawNames = {}
        ret = self.readObject(rawContent[self.charCounter:], 'name')
        if ret[0] == -1:
            if ret[1] != 'Empty content reading object':
                if get_parser_context().force_mode:
                    self.pdfFile.addError(ret[1])
                    name = None
                else:
                    return ret
            else:
                name = None
        else:
            name = ret[1]
        while name != None:
            key = name.getValue()
            rawNames[key] = name
            rawValue = rawContent[self.charCounter:]
            ret = self.readObject(rawValue)
            if ret[0] == -1:
                if get_parser_context().force_mode:
                    self.pdfFile.addError('Bad object for '+str(key)+' key')
                    ret = self.readUntilSymbol(rawContent, '/')
                    if ret[0] == -1:
                        elements[key] = PDFString(rawValue)
                    else:
                        elements[key] = PDFString(ret[1])
                    self.readSpaces(rawContent)
                else:
                    return (-1,'Bad object for '+str(key)+' key')
            else:
                value = ret[1]
                elements[key] = value
            ret = self.readObject(rawContent[self.charCounter:], 'name')
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if get_parser_context().force_mode:
                        self.pdfFile.addError(ret[1])
                        name = None
                    else:
                        return ret
                else:
                    name = None
            else:
                name = ret[1]
                if name != None and name.getType() != 'name':
                    errorMessage = 'Name object not found in dictionary key'
                    if get_parser_context().force_mode:
                        self.pdfFile.addError(errorMessage)
                        name = None
                    else:
                        return (-1, errorMessage)
        try:
            pdfDictionary = PDFDictionary(rawContent, elements, rawNames)
        except Exception as e:
            errorMessage = 'Error creating PDFDictionary'
            if e.message != '':
                errorMessage += ': '+e.message
            return (-1, errorMessage)
        self.charCounter = realCounter
        return (0,pdfDictionary)

    def createPDFStream(self, dict, stream):
        '''
            Create a PDFStream or PDFObjectStream instance from the raw content of the PDF file
            @param dict Raw content of the dictionary object.
            @param stream Raw content of the stream.
            @return A tuple (status,statusContent), where statusContent is the PDFStream or PDFObjectStream in case status = 0 or an error in case status = -1
        '''
        realCounter = self.charCounter
        self.charCounter = 0
        elements = {}
        rawNames = {}
        ret = self.readObject(dict[self.charCounter:], 'name')
        if ret[0] == -1:
            if ret[1] != 'Empty content reading object':
                if get_parser_context().force_mode:
                    self.pdfFile.addError(ret[1])
                    name = None
                else:
                    return ret
            else:
                name = None
        else:
            name = ret[1]    
        while name != None:
            key = name.getValue()
            rawNames[key] = name
            ret = self.readObject(dict[self.charCounter:])
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if get_parser_context().force_mode:
                        self.pdfFile.addError(ret[1])
                        value = None
                    else:
                        return ret
                else:
                    value = None
            else:
                value = ret[1]
            elements[key] = value
            ret = self.readObject(dict[self.charCounter:], 'name')
            if ret[0] == -1:
                if ret[1] != 'Empty content reading object':
                    if get_parser_context().force_mode:
                        self.pdfFile.addError(ret[1])
                        name = None
                    else:
                        return ret
                else:
                    name = None
            else:
                name = ret[1]
        if '/Type' in elements and elements['/Type'].getValue() == '/ObjStm':
            try:
                pdfStream = PDFObjectStream(dict, stream, elements, rawNames, {})
            except Exception as e:
                errorMessage = 'Error creating PDFObjectStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        else:
            try:
                pdfStream = PDFStream(dict, stream, elements, rawNames)
            except Exception as e:
                errorMessage = 'Error creating PDFStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        self.charCounter = realCounter
        return (0,pdfStream)

    def createPDFCrossRefSection (self, rawContent, offset):
        '''
            Create a PDFCrossRefSection instance from the raw content of the PDF file
            @param rawContent String with the raw content of the PDF body (string)
            @param offset Offset of the cross reference section in the PDF file (int)
            @return A tuple (status,statusContent), where statusContent is the PDFCrossRefSection in case status = 0 or an error in case status = -1
        '''
        if not isinstance(rawContent, str):
            return (-1,'Empty xref content')
        entries = []
        auxOffset = 0
        subSectionSize = 0
        self.charCounter = 0
        pdfCrossRefSection = PDFCrossRefSection()
        pdfCrossRefSection.setOffset(offset)
        pdfCrossRefSection.setSize(len(rawContent))
        pdfCrossRefSubSection = None
        beginSubSectionRE = re.compile(r'(\d{1,10})\s(\d{1,10})\s*$')
        entryRE = re.compile(r'(\d{10})\s(\d{5})\s([nf])')
        ret = self.readSymbol(rawContent, 'xref')
        if ret[0] == -1:
            return ret
        auxOffset += self.charCounter
        lines = self.getLines(rawContent[self.charCounter:])
        if lines == []:
            if get_parser_context().force_mode:
                pdfCrossRefSubSection = PDFCrossRefSubSection(0, offset = -1)
                self.pdfFile.addError('No entries in xref section')
            else:
                return (-1,'Error: No entries in xref section!!')
        else:
            for line in lines:
                match = re.findall(beginSubSectionRE, line)
                if match != []:
                    if pdfCrossRefSubSection != None:        
                        pdfCrossRefSubSection.setSize(subSectionSize)
                        pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
                        pdfCrossRefSubSection.setEntries(entries)
                        subSectionSize = 0
                        entries = []
                    try:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(match[0][0], match[0][1], offset=auxOffset)
                    except:
                        return (-1,'Error creating PDFCrossRefSubSection')
                else:
                    match = re.findall(entryRE,line)
                    if match != []:
                        try:
                            pdfCrossRefEntry = PDFCrossRefEntry(match[0][0], match[0][1], match[0][2], offset=auxOffset)
                        except:
                            return (-1,'Error creating PDFCrossRefEntry')
                        entries.append(pdfCrossRefEntry)
                    else:
                        #TODO: comments in line or spaces/\n\r...?
                        if get_parser_context().force_mode:
                            if pdfCrossRefSubSection != None:
                                pdfCrossRefSubSection.addError('Bad format for cross reference entry: '+line)
                            else:
                                pdfCrossRefSubSection = PDFCrossRefSubSection(0, offset=-1)
                                self.pdfFile.addError('Bad xref section')
                        else:
                            return (-1,'Bad format for cross reference entry')
                auxOffset += len(line)
                subSectionSize += len(line)
            else:
                if not pdfCrossRefSubSection:
                    if get_parser_context().force_mode:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(0, len(entries), offset=auxOffset)
                        self.pdfFile.addError('Missing xref section header')
                    else:
                        return (-1, 'Missing xref section header')
        pdfCrossRefSubSection.setSize(subSectionSize)
        pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
        pdfCrossRefSubSection.setEntries(entries)
        return (0,pdfCrossRefSection)

    def createPDFCrossRefSectionFromStream (self, objectStream):
        '''
            Create a PDFCrossRefSection instance from the raw content of the PDF file
            @param objectStream Object stream object (PDFIndirectObject).
            @return A tuple (status,statusContent), where statusContent is the PDFCrossRefSection in case status = 0 or an error in case status = -1
        '''
        index = 0
        firstEntry = 0
        entries = []
        numObjects = 0
        numSubsections = 1
        bytesPerField = [1,2,1]
        entrySize = 4
        subsectionIndexes = []
        if objectStream != None:
            pdfCrossRefSection = PDFCrossRefSection()
            pdfCrossRefSection.setXrefStreamObject(objectStream.getId())
            xrefObject = objectStream.getObject()
            if xrefObject != None:
                if xrefObject.hasElement('/Size'):
                    sizeObject = xrefObject.getElementByName('/Size')
                    if sizeObject != None and sizeObject.getType() == 'integer':
                        numObjects = sizeObject.getRawValue()
                        subsectionIndexes = [0,numObjects]
                    else:
                        errorMessage = 'Bad object type for /Size element'
                        if get_parser_context().force_mode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                else:
                    errorMessage = 'Element /Size not found'
                    if get_parser_context().force_mode:
                        pdfCrossRefSection.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                    
                if xrefObject.hasElement('/W'):
                    bytesPerFieldObject = xrefObject.getElementByName('/W')
                    if bytesPerFieldObject.getType() == 'array':
                        bytesPerField = bytesPerFieldObject.getElementRawValues()
                        if len(bytesPerField) != 3:
                            errorMessage = 'Bad content of /W element'
                            if get_parser_context().force_mode:
                                pdfCrossRefSection.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        else:
                            entrySize = 0
                            for num in bytesPerField:
                                entrySize += num
                    else:
                        errorMessage = 'Bad object type for /W element'
                        if get_parser_context().force_mode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                else:
                    errorMessage = 'Element /W not found'
                    if get_parser_context().force_mode:
                        pdfCrossRefSection.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                    
                if xrefObject.hasElement('/Index'):
                    subsectionIndexesObject = xrefObject.getElementByName('/Index')
                    if subsectionIndexesObject.getType() == 'array':
                        subsectionIndexes = subsectionIndexesObject.getElementRawValues()
                        if len(subsectionIndexes) % 2 != 0:
                            errorMessage = 'Bad content of /Index element'
                            if get_parser_context().force_mode:
                                pdfCrossRefSection.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                        else:
                            numSubsections = len(subsectionIndexes) / 2
                    else:
                        errorMessage = 'Bad object type for /Index element'
                        if get_parser_context().force_mode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
        
                pdfCrossRefSection.setBytesPerField(bytesPerField)
                stream = xrefObject.getStream()
                for i in range(0,len(stream),entrySize):
                    entryBytes = stream[i:i+entrySize]
                    try:
                        if bytesPerField[0] == 0:
                            f1 = 1
                        else:
                            f1 = int(entryBytes[:bytesPerField[0]].encode('hex'),16)
                        if bytesPerField[1] == 0:
                            f2 = 0
                        else:
                            f2 = int(entryBytes[bytesPerField[0]:bytesPerField[0]+bytesPerField[1]].encode('hex'),16)
                        if bytesPerField[2] == 0:
                            f3 = 0
                        else:
                            f3 = int(entryBytes[bytesPerField[0]+bytesPerField[1]:].encode('hex'),16)
                    except:
                        errorMessage = 'Error in hexadecimal conversion'
                        if get_parser_context().force_mode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    try:
                        pdfCrossRefEntry = PDFCrossRefEntry(f2,f3,f1)
                    except:
                        errorMessage = 'Error creating PDFCrossRefEntry'
                        if get_parser_context().force_mode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    entries.append(pdfCrossRefEntry)
                for i in range(numSubsections):
                    firstObject = subsectionIndexes[index]
                    numObjectsInSubsection = subsectionIndexes[index+1]
                    try:
                        pdfCrossRefSubSection = PDFCrossRefSubSection(firstObject,numObjectsInSubsection)
                    except:
                        errorMessage = 'Error creating PDFCrossRefSubSection'
                        if get_parser_context().force_mode:
                            pdfCrossRefSection.addError(errorMessage)
                        else:
                            return (-1, errorMessage)
                    pdfCrossRefSubSection.setEntries(entries[firstEntry:firstEntry+numObjectsInSubsection])
                    pdfCrossRefSection.addSubsection(pdfCrossRefSubSection)
                    firstentry = numObjectsInSubsection
                    index += 2
                return (0,pdfCrossRefSection)
            else:
                return (-1,'The object stream is None')
        else:
            return (-1,'The indirect object stream is None')

    def createPDFTrailer (self, rawContent, offset, streamPresent = False) :
        '''
            Create a PDFTrailer instance from the raw content of the PDF file
            @param rawContent String with the raw content of the PDF body (string)
            @param offset Offset of the trailer in the PDF file (int)
            @param streamPresent It specifies if an object stream exists in the PDF body
            @return A tuple (status,statusContent), where statusContent is the PDFTrailer in case status = 0 or an error in case status = -1
        '''
        trailer = None
        self.charCounter = 0
        if not isinstance(rawContent,str):
            return (-1,'Empty trailer content')
        self.readSymbol(rawContent, 'trailer')    
        ret = self.readObject(rawContent[self.charCounter:],'dictionary')
        if ret[0] == -1:
            dict = PDFDictionary('')
            dict.addError('Error creating the trailer dictionary')
        else:
            dict = ret[1]
        ret = self.readSymbol(rawContent, 'startxref')
        if ret[0] == -1:
            try:
                trailer = PDFTrailer(dict, streamPresent = streamPresent)
            except Exception as e:
                errorMessage = 'Error creating PDFTrailer'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        else:
            ret = self.readUntilEndOfLine(rawContent)
            if ret[0] == -1:
                if get_parser_context().force_mode:
                    lastXrefSection = -1
                    self.pdfFile.addError('EOL not found while looking for the last cross reference section')
                else:
                    return (-1,'EOL not found while looking for the last cross reference section')
            else:
                lastXrefSection = ret[1]
            try:
                trailer = PDFTrailer(dict, lastXrefSection, streamPresent = streamPresent)
            except Exception as e:
                errorMessage = 'Error creating PDFTrailer'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
        trailer.setOffset(offset)
        eofOffset = rawContent.find('%%EOF')
        if eofOffset == -1:
            trailer.setEOFOffset(eofOffset)
            trailer.setSize(len(rawContent))
        else:
            trailer.setEOFOffset(offset+eofOffset)
            trailer.setSize(eofOffset)
        return (0,trailer)
    
    def createPDFTrailerFromStream (self, indirectObject, rawContent) :
        '''
            Create a PDFTrailer instance from the raw content of the PDF file
            @param indirectObject Object stream object (PDFIndirectObject).
            @param rawContent String with the raw content of the PDF body (string)
            @return A tuple (status,statusContent), where statusContent is the PDFTrailer in case status = 0 or an error in case status = -1
        '''
        trailer = None
        self.charCounter = 0
        trailerElements = ['/Size','/Prev','/Root','/Encrypt','/Info','/ID']
        dict = {}
        if indirectObject != None:
            xrefStreamObject = indirectObject.getObject()
            if xrefStreamObject != None:
                for element in trailerElements:
                    if xrefStreamObject.hasElement(element):
                        dict[element] = xrefStreamObject.getElementByName(element)
                try:
                    dict = PDFDictionary('',dict)
                except Exception as e:
                    if get_parser_context().force_mode:
                        dict = None
                    else:
                        errorMessage = 'Error creating PDFDictionary'
                        if e.message != '':
                            errorMessage += ': '+e.message
                        return (-1, errorMessage)
                if not isinstance(rawContent,str):
                    if get_parser_context().force_mode:
                        lastXrefSection = -1
                    else:
                        return (-1,'Empty trailer content')
                else:
                    ret = self.readUntilSymbol(rawContent, 'startxref')
                    if ret[0] == -1 and not get_parser_context().force_mode:
                        return ret
                    ret = self.readSymbol(rawContent, 'startxref')
                    if ret[0] == -1 and not get_parser_context().force_mode:
                        return ret
                    ret = self.readUntilEndOfLine(rawContent)
                    if ret[0] == -1:
                        if not get_parser_context().force_mode:
                            return ret
                        lastXrefSection = -1
                    else:
                        lastXrefSection = ret[1]
                try:
                    trailer = PDFTrailer(dict, lastXrefSection)
                except Exception as e:
                    errorMessage = 'Error creating PDFTrailer'
                    if e.message != '':
                        errorMessage += ': '+e.message
                    return (-1, errorMessage)
                trailer.setXrefStreamObject(indirectObject.getId())
            else:
                return (-1,'Object stream is None')
        else:
            return (-1,'Indirect object stream is None')
        return (0,trailer)

    def getIndirectObjects(self, content, looseMode = False):
        '''
            This function returns an array of raw indirect objects of the PDF file given the raw body.
            @param content: string with the raw content of the PDF body.
            @param looseMode: boolean specifies if the parsing process should search for the endobj tag or not.
            @return matchingObjects: array of tuples (object_content,object_header).
        '''
        matchingObjects = []
        if not isinstance(content,str):
            return matchingObjects
        if not looseMode:
            regExp = re.compile(r'((\d{1,10}\s\d{1,10}\sobj).*?endobj)',re.DOTALL)
            matchingObjects = regExp.findall(content)
        else:
            regExp = re.compile(r'((\d{1,10}\s\d{1,10}\sobj).*?)\s\d{1,10}\s\d{1,10}\sobj',re.DOTALL)
            matchingObjectsAux = regExp.findall(content)
            while matchingObjectsAux != []:
                if matchingObjectsAux[0] != []:
                    objectBody = matchingObjectsAux[0][0]
                    matchingObjects.append(matchingObjectsAux[0])
                    content = content[content.find(objectBody)+len(objectBody):]
                    matchingObjectsAux = regExp.findall(content)
                else:
                    matchingObjectsAux = []
            lastObject = re.findall(r'(\d{1,5}\s\d{1,5}\sobj)',content,re.DOTALL)
            if lastObject != []:
                content = content[content.find(lastObject[0]):]
                matchingObjects.append((content,lastObject[0]))
        return matchingObjects
        
    def getLines(self, content):
        '''
            Simple function to return the lines separated by end of line characters
            @param content
            @return List with the lines, without end of line characters
        '''
        lines = []
        i = 0
        while i < len(content):
            if content[i] == '\r':
                lines.append(content[:i])
                if content[i+1] == '\n':
                    i += 1
                content = content[i+1:]
                i = 0
            elif content[i] == '\n':
                lines.append(content[:i])
                content = content[i+1:]
                i = 0
            i += 1
        if i > 0:
            lines.append(content)
        return lines
    
    def readObject(self, content, objectType = None, forceMode = False, looseMode = False):
        '''
            Method to parse the raw body of the PDF file and obtain PDFObject instances
            @param content
            @param objectType
            @param forceMode
            @param looseMode
            @return A tuple (status,statusContent), where statusContent is a PDFObject instance in case status = 0 or an error in case status = -1
        '''
        if len(content) == 0 or content[:6] == 'endobj':
            return (-1,'Empty content reading object')
        pdfObject = None
        oldCounter = self.charCounter
        self.charCounter = 0
        if objectType != None:
            objectsTypeArray = [self.delimiters[i][2] for i in range(len(self.delimiters))]
            index = objectsTypeArray.index(objectType)
            if index != -1:
                delimiters = [self.delimiters[index]]
            else:
                if get_parser_context().force_mode:
                    self.pdfFile.addError('Unknown object type while parsing object')
                    return (-1,'Unknown object type')
                else:
                    sys.exit('Error: Unknown object type!!')
        else:
            delimiters = self.delimiters
        for delim in delimiters:
            ret = self.readSymbol(content, delim[0])
            if ret[0] != -1:
                if delim[2] == 'dictionary':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] == -1:
                        dictContent = ''
                    else:
                        dictContent = ret[1]
                    nonDictContent = content[self.charCounter:]
                    streamFound = re.findall(r'[>\s]stream', nonDictContent)
                    if streamFound:
                        ret = self.readUntilSymbol(content, 'stream')
                        if ret[0] == -1:
                            return ret
                        auxDict = ret[1]
                        self.readSymbol(content, 'stream', False)
                        self.readUntilEndOfLine(content)
                        self.readSymbol(content, '\r', False)
                        self.readSymbol(content, '\n', False)
                        ret = self.readUntilSymbol(content, 'endstream')
                        if ret[0] == -1:
                            stream = content[self.charCounter:]
                        else:
                            stream = ret[1]
                            self.readSymbol(content, 'endstream')
                        ret = self.createPDFStream(dictContent, stream)
                        if ret[0] == -1:
                            return ret
                        pdfObject = ret[1]
                        break
                    else:
                        if ret[0] != -1:
                            self.readSymbol(content, delim[1])
                            ret = self.createPDFDictionary(dictContent)
                            if ret[0] == -1:
                                return ret
                            pdfObject = ret[1]
                        else:
                            pdfObject = PDFDictionary(content)
                            pdfObject.addError('Closing delimiter not found in dictionary object')
                        break
                elif delim[2] == 'string':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        stringContent = ret[1]
                        self.readSymbol(content, delim[1])
                        pdfObject = PDFString(stringContent)
                    else:
                        pdfObject = PDFString(content)
                        pdfObject.addError('Closing delimiter not found in string object')
                    break
                elif delim[2] == 'hexadecimal':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        hexContent = ret[1]
                        self.readSymbol(content, delim[1])
                        pdfObject = PDFHexString(hexContent)
                    else:
                        pdfObject = PDFHexString(content)
                        pdfObject.addError('Closing delimiter not found in hexadecimal object')
                    break
                elif delim[2] == 'array':
                    ret = self.readUntilClosingDelim(content, delim)
                    if ret[0] != -1:
                        arrayContent = ret[1]
                        self.readSymbol(content, delim[1])
                        ret = self.createPDFArray(arrayContent)
                        if ret[0] == -1:
                            return ret
                        pdfObject = ret[1]
                    else:
                        pdfObject = PDFArray(content)
                        pdfObject.addError('Closing delimiter not found in array object')
                    break
                elif delim[2] == 'name':
                    ret,raw = self.readUntilNotRegularChar(content)
                    pdfObject = PDFName(raw)
                    break
                elif delim[2] == 'comment':
                    ret = self.readUntilEndOfLine(content)
                    if ret[0] == 0:
                        self.comments.append(ret[1])
                        self.readSpaces(content)
                        pdfObject = self.readObject(content[self.charCounter:],objectType)
                    else:
                        return ret
                    break
        else:
            if content[0] == 't' or content[0] == 'f':
                ret,raw = self.readUntilNotRegularChar(content)
                pdfObject = PDFBool(raw)
            elif content[0] == 'n':
                ret,raw = self.readUntilNotRegularChar(content)
                pdfObject = PDFNull(raw)
            elif re.findall(r'^(\d{1,10}\s{1,3}\d{1,10}\s{1,3}R)', content, re.DOTALL) != []:
                ret,id = self.readUntilNotRegularChar(content)
                ret,genNumber = self.readUntilNotRegularChar(content)
                ret = self.readSymbol(content, 'R')
                if ret[0] == -1:
                    return ret
                pdfObject = PDFReference(id, genNumber)
            elif re.findall(r'^([-+]?\.?\d{1,15}\.?\d{0,15})', content, re.DOTALL) != []:
                ret,num = self.readUntilNotRegularChar(content)
                pdfObject = PDFNum(num)
            else:
                self.charCounter += oldCounter
                return (-1,'Object not found')
        self.charCounter += oldCounter
        return (0,pdfObject)

    def readSpaces(self, string):
        '''
            Reads characters until all spaces chars have been read
            @param string 
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(string,str):
            return (-1,'Bad string')
        spacesCounter = self.charCounter
        for i in range(self.charCounter,len(string)):
            if string[i] not in spacesChars:
                break
            self.charCounter += 1
        spacesCounter -= self.charCounter
        return (0,spacesCounter)

    def readSymbol(self, string, symbol, deleteSpaces = True):
        '''
            Reads a given symbol from the string, removing comments and spaces (if specified)
            @param string
            @param symbol
            @param deleteSpaces
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(string,str):
            return (-1,'Bad string')
        oldCharCounter = self.charCounter
        if self.charCounter > len(string)-1:
            errorMessage = 'EOF while looking for symbol "'+symbol+'"'
            self.pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        while string[self.charCounter] == '%':
            ret = self.readUntilEndOfLine(string)
            if ret[0] == -1:
                return ret
            self.comments.append(ret[1])
            self.readSpaces(string)
        symbolToRead = string[self.charCounter:self.charCounter+len(symbol)]
        if symbolToRead != symbol:
            errorMessage = 'Symbol "'+symbol+'" not found while parsing'
            #self.pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        self.charCounter += len(symbol)
        if deleteSpaces:
            self.readSpaces(string)
        return (0,self.charCounter - oldCharCounter)

    def readUntilClosingDelim(self, content, delim):
        '''
            Method that reads characters until it finds the closing delimiter
            @param content
            @param delim
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        output = ''
        if not isinstance(content,str):
            return (-1,'Bad string')
        newContent = content[self.charCounter:]
        numOpeningDelims = newContent.count(delim[0]) + 1
        numClosingDelims = newContent.count(delim[1])
        if numClosingDelims == 0:
            errorMessage = 'No closing delimiter found'
            self.pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        elif numClosingDelims == 1:
            index = newContent.rfind(delim[1])
            self.charCounter += index
            return (0,newContent[:index])
        else:
            indexChar = 0
            prevChar = ''
            while indexChar != len(newContent):
                char = newContent[indexChar]
                if indexChar == len(newContent) - 1:
                    nextChar = ''
                else:
                    nextChar = newContent[indexChar+1]
                if char == delim[1] or (char + nextChar) == delim[1]:
                    if char != ')' or indexChar == 0 or newContent[indexChar-1] != '\\':
                        return (0,output)
                    else:
                        output += char
                        indexChar += 1
                        self.charCounter += 1
                elif (char == '(' and prevChar != '\\') or (char in ['[','<'] and delim[0] != '('):
                    if (char + nextChar) != '<<':
                        delimIndex = delimiterChars.index(char)
                        self.charCounter += 1
                        ret = self.readUntilClosingDelim(content, self.delimiters[delimIndex])
                        if ret[0] != -1:
                            tempObject = char + ret[1]
                        else:
                            return ret
                    else:
                        delimIndex = delimiterChars.index(char + nextChar)
                        self.charCounter += 2
                        ret = self.readUntilClosingDelim(content, self.delimiters[delimIndex])
                        if ret[0] != -1:
                            tempObject = char + nextChar + ret[1]
                        else:
                            return ret
                    ret = self.readSymbol(content, self.delimiters[delimIndex][1], False)
                    if ret[0] != -1:
                        tempObject += self.delimiters[delimIndex][1]
                    else:
                        return ret
                    indexChar += len(tempObject)
                    output += tempObject
                else:
                    indexChar += 1
                    self.charCounter += 1
                    output += char
                    prevChar = char            
            else:
                errorMessage = 'No closing delimiter found'
                self.pdfFile.addError(errorMessage)
                return (-1, errorMessage)
    
    def readUntilEndOfLine(self, content):
        '''
            This function reads characters until the end of line
            @param content
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(content,str):
            return (-1,'Bad string')
        errorMessage = []
        oldCharCounter = self.charCounter
        tmpContent = content[self.charCounter:]
        for char in tmpContent:
            if char == '\r' or char == '\n':
                return (0,content[oldCharCounter:self.charCounter])
            self.charCounter += 1
        else:
            errorMessage = 'EOL not found'
            self.pdfFile.addError(errorMessage)
            return (-1, errorMessage)

    def readUntilLastSymbol(self, string, symbol):
        '''
            Method that reads characters until it finds the last appearance of 'symbol'
            @param string
            @param symbol
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(string,str):
            return (-1,'Bad string')
        newString = string[self.charCounter:]
        index = newString.rfind(symbol)
        if index == -1:
            errorMessage = 'Symbol "'+symbol+'" not found'
            self.pdfFile.addError(errorMessage)
            return (-1, errorMessage)
        self.charCounter += index
        return (0,newString[:index])
            
    def readUntilNotRegularChar(self, string):
        '''
            Reads the regular chars of the string until it reachs a non-regular char. Then it removes spaces chars.
            @param string 
            @return A tuple (status,statusContent), where statusContent is the number of characters read in case status = 0 or an error in case status = -1
        '''
        readChars = ''
        if not isinstance(string,str):
            return (-1,'Bad string')
        notRegChars = spacesChars + delimiterChars
        for i in range(self.charCounter,len(string)):
            if string[i] in notRegChars:
                self.readSpaces(string)
                break
            readChars += string[i]
            self.charCounter += 1
        return (0,readChars)
            
    def readUntilSymbol(self, string, symbol):
        '''
            Method that reads characters until it finds the first appearance of 'symbol'
            @param string
            @param symbol
            @return A tuple (status,statusContent), where statusContent is the characters read in case status = 0 or an error in case status = -1
        '''
        if not isinstance(string,str):
            return (-1,'Bad string')
        newString = string[self.charCounter:]
        index = newString.find(symbol)
        if index == -1:
            errorMessage = 'Symbol "'+symbol+'" not found'
            return (-1, errorMessage)
        self.charCounter += index
        return (0,newString[:index])
