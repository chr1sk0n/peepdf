"""PDF structural components (cross-reference sections, body, trailer, and PDFFile)."""

import aes as AES
import hashlib
import os
import re
import struct
import sys

from JSAnalysis import analyseJS, isJavascript
from parser_context import get_parser_context
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

class PDFCrossRefSection :
    def __init__(self) :
        self.errors = []
        self.streamObject = None
        self.offset = 0
        self.size = 0
        self.subsections = [] # PDFCrossRefSubsection []
        self.bytesPerField = []

    def addEntry(self, objectId, newEntry):
        prevSubsection = 0
        errorMessage = ''
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            ret = subsection.addEntry(newEntry, objectId)
            if ret[0] != -1:
                break
            else:
                errorMessage = ret[1]
                self.addError(errorMessage)
            if subsection.getFirstObject() + subsection.getNumObjects() < objectId:
                prevSubsection = i
        else:
            try:
                newSubsection = PDFCrossRefSubSection(objectId, 1, [newEntry])
            except:
                errorMessage = 'Error creating new PDFCrossRefSubSection'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
            self.subsections.insert(prevSubsection, newSubsection)
        if errorMessage != '':
            return (-1,errorMessage)
        else:
            return (0,'')
        
    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def addSubsection(self, subsection):
        self.subsections.append(subsection)
    
    def delEntry(self, objectId):
        prevSubsection = 0
        errorMessage = ''
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            numEntry = subsection.getIndex(objectId)
            if numEntry != None:
                if subsection.getNumObjects() == 1:
                    self.subsections.remove(subsection)
                else:
                    ret = subsection.delEntry(objectId)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(ret[1])
                        continue
        if errorMessage != '':
            return (-1,errorMessage)
        else:
            return (0,'')
    
    def getBytesPerField(self):
        return self.bytesPerField

    def getErrors(self):
        return self.errors

    def getFreeObjectIds(self):
        ids = []
        for subsection in self.subsections:
            ids += subsection.getFreeObjectIds()
        return ids
    
    def getNewObjectIds(self):
        ids = []
        for subsection in self.subsections:
            ids += subsection.getNewObjectIds()
        return ids
    
    def getOffset(self):
        return self.offset
    
    def getSize(self):
        return self.size
    
    def getStats(self):
        stats = {}
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        if self.inStream():
            stats['Stream'] = str(self.streamObject)
        else:
            stats['Stream'] = None
        stats['Subsections'] = []
        for i in range(len(self.subsections)):
            subsection = self.subsections[i]
            subStats = {}
            subStats['Entries'] = str(len(subsection.getEntries()))
            if subsection.isFaulty():
                subStats['Errors'] = str(len(subsection.getErrors()))
            else:
                subStats['Errors'] = None
            stats['Subsections'].append(subStats)
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats

    def getSubsectionsArray(self):
        return self.subsections

    def getSubsectionsNumber(self):
        return len(self.subsections)

    def getXrefStreamObject(self):
        return self.streamObject

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def inStream(self):
        if self.streamObject != None:
            return True
        else:
            return False
        
    def setBytesPerField(self, array):
        self.bytesPerField = array        

    def setOffset(self, offset):
        self.offset = offset
                
    def setSize(self, newSize):
        self.size = newSize

    def setXrefStreamObject(self, id):
        self.streamObject = id

    def toFile(self):
        output = 'xref' + newLine
        for subsection in self.subsections:
            output += subsection.toFile()
        return output

    def updateOffset(self, objectId, newOffset):
        for subsection in self.subsections:
            updatedEntry = subsection.getEntry(objectId)
            if updatedEntry != None: 
                updatedEntry.setObjectOffset(newOffset)
                ret = subsection.setEntry(objectId, updatedEntry)
                if ret[0] == -1:
                    self.addError(ret[1])
                return ret
        else:
            errorMessage = 'Object entry not found'
            self.addError(errorMessage)
            return (-1,errorMessage)


class PDFCrossRefSubSection:
    def __init__(self, firstObject, numObjects = 0, newEntries = [], offset = 0) :
        self.errors = []
        self.offset = offset
        self.size = 0
        self.firstObject = int(firstObject)
        self.numObjects = int(numObjects)
        self.entries = newEntries

    def addEntry(self, newEntry, objectId = None):
        if objectId == None:
            self.entries.append(newEntry)
            self.numObjects += 1
            return (0,self.numObjects)
        else:
            numEntry = self.getIndex(objectId)
            if numEntry != None:
                self.entries.insert(numEntry, newEntry)
                self.numObjects += 1
                return (0,self.numObjects)
            else:
                if self.firstObject == objectId + 1:
                    self.entries.insert(0, newEntry)
                    self.firstObject = objectId
                    self.numObjects += 1
                    return (0,self.numObjects)
                elif objectId == self.firstObject + self.numObjects:
                    self.entries.append(newEntry)
                    self.numObjects += 1
                    return (0,self.numObjects)
                else:
                    errorMessage = 'Unspecified error'
                    self.addError(errorMessage)
                    return (-1,errorMessage)
                return (0,self.numObjects)
    
    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def delEntry(self, objectId):
        numEntry = self.getIndex(objectId)
        if numEntry == None:
            errorMessage = 'Entry not found'
            self.addError(errorMessage)
            return (-1,errorMessage)
        if numEntry == 0:
            self.entries.pop(numEntry)
            self.firstObject = objectId + 1
            self.numObjects -= 1
        elif numEntry == self.numObjects - 1:
            self.entries.pop(numEntry)
            self.numObjects -= 1
        else:
            entry = self.entries[numEntry]
            numPrevFree = self.getPrevFree(numEntry)
            numNextFree = self.getNextFree(numEntry)
            nextObject = self.getObjectId(numNextFree)
            if numPrevFree != None:
                prevEntry = self.entries[numPrevFree]
                prevEntry.setNextObject(objectId)
                self.entries[numPrevFree] = prevEntry
            entry.setType('f')
            if nextObject == None:
                entry.setNextObject(0)
            else:
                entry.setNextObject(nextObject)
            entry.incGenNumber()
            self.entries[numEntry] = entry
        return (0,numEntry)    

    def getEntries(self):
        return self.entries
        
    def getEntry(self, objectId):
        numEntry = self.getIndex(objectId)
        if numEntry != None:
            return self.entries[numEntry]
        else:
            return None
        
    def getErrors(self):
        return self.errors

    def getFirstObject(self):
        return self.firstObject

    def getFreeObjectIds(self):
        ids = []
        for i in range(len(self.entries)):
            if self.entries[i].getType() == 'f':
                ids.append(self.getObjectId(i))
        return ids    
    
    def getIndex(self, objectId):
        objectIds = list(range(self.firstObject,self.firstObject+self.numObjects))
        if objectId in objectIds:
            return objectIds.index(objectId)
        else:
            return None

    def getNextFree(self, numEntry):
        for i in range(numEntry + 1,self.numObjects):
            if self.entries[i].getType() == 'f':
                return i
        else:
            return None
        
    def getNewObjectIds(self):
        ids = []
        for i in range(len(self.entries)):
            if self.entries[i].getType() == 'n':
                ids.append(self.getObjectId(i))
        return ids

    def getNumObjects(self):
        return self.numObjects

    def getObjectId(self, numEntry):
        return self.firstObject + numEntry
            
    
    def getOffset(self):
        return self.offset
    
        
    def getPrevFree(self, numEntry):
        for i in range(numEntry):
            if self.entries[i].getType() == 'f':
                return i
        else:
            return None

    def getSize(self):
        return self.size
    
    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def setEntry(self, objectId, newEntry):
        numEntry = self.getIndex(objectId)
        if numEntry != None:
            self.entries[numEntry] = newEntry
            return (0,numEntry)
        else:
            errorMessage = 'Entry not found'
            self.addError(errorMessage)
            return (-1,errorMessage)
        
    def setEntries(self, newEntries):
        self.entries = newEntries

    def setFirstObject(self, newFirst):
        self.firstObject = newFirst
        
    def setNumObjects(self, newNumObjects):
        self.numObjects = newNumObjects

    def setOffset(self, offset):
        self.offset = offset
        
    def setSize(self, newSize):
        self.size = newSize
    
    def toFile(self):
        output = str(self.firstObject) + ' ' + str(self.numObjects) + newLine
        for entry in self.entries:
            output += entry.toFile()
        return output
            

class PDFCrossRefEntry:
    def __init__(self, firstValue, secondValue, type, offset = 0) :
        self.errors = []
        self.offset = offset
        self.objectStream = None
        self.indexObject = None
        self.genNumber = None
        self.objectOffset = None
        self.nextObject = None
        self.entryType = type
        if type == 'f' or type == 0:
            self.nextObject = int(firstValue)
            self.genNumber = int(secondValue)            
        elif type == 'n' or type == 1:
            self.objectOffset = int(firstValue)
            self.genNumber = int(secondValue)            
        elif type == 2:
            self.objectStream = int(firstValue)
            self.indexObject = int(secondValue)
        else:
            if get_parser_context().force_mode:
                self.addError('Error parsing xref entry')
            else:
                return (-1,'Error parsing xref entry')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def getEntryBytes(self, bytesPerField):
        bytesString = ''
        errorMessage = ''
            
        if self.entryType == 'f' or self.entryType == 0:
            type = 0
            firstValue = self.nextObject
            secondValue = self.genNumber
        elif self.entryType == 'n' or self.entryType == 1:
            type = 1
            firstValue = self.objectOffset
            secondValue = self.genNumber
        else:
            type = 2
            firstValue = self.objectStream
            secondValue = self.indexObject

        if bytesPerField[0] != 0:
            ret = numToHex(type,bytesPerField[0])
            if ret[0] == -1:
                errorMessage = ret[1]
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                    ret = numToHex(0,bytesPerField[0])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if bytesPerField[1] != 0:
            ret = numToHex(firstValue,bytesPerField[1])
            if ret[0] == -1:
                errorMessage = ret[1]
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                    ret = numToHex(0,bytesPerField[1])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if bytesPerField[2] != 0:
            ret = numToHex(secondValue,bytesPerField[2])
            if ret[0] == -1:
                errorMessage = ret[1]
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                    ret = numToHex(0,bytesPerField[1])
                    bytesString += ret[1]
                else:
                    return ret
            else:
                bytesString += ret[1]
        if errorMessage != '':
            return (-1,errorMessage)    
        return (0,bytesString) 
    
    def getErrors(self):
        return self.errors
    
    def getGenNumber(self):
        return self.genNumber

    def getIndexObject(self):
        return self.indexObject
    
    def getNextObject(self):
        return self.nextObject

    def getObjectOffset(self):
        return self.objectOffset

    def getObjectStream(self):
        return self.objectStream
            
    def getOffset(self):
        return self.offset

    def getType(self):
        return self.entryType
    
    def incGenNumber(self):
        self.genNumber += 1
        
    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def setGenNumber(self, newGenNumber):
        self.genNumber = newGenNumber
        
    def setIndexObject(self, index):
        self.indexObject = index

    def setNextObject(self, newNextObject):
        self.nextObject = newNextObject

    def setObjectOffset(self, newOffset):
        self.objectOffset = newOffset
                    
    def setObjectStream(self, id):
        self.objectStream = id
        
    def setOffset(self, offset):
        self.offset = offset

    def setType(self, newType):
        self.entryType = newType
        
            
    def toFile(self):
        output = ''
        if self.entryType == 'n':
            ret = numToString(self.objectOffset,10)
            if ret[0] != -1:
                output += ret[1]
        elif self.entryType == 'f':
            ret = numToString(self.nextObject,10)
            if ret[0] != -1:
                output += ret[1]
        output += ' '
        ret = numToString(self.genNumber, 5)
        if ret[0] != -1:
            output += ret[1]
        output += ' '
        output += self.entryType
        if len(newLine) == 2:
            output += newLine
        else:
            output += ' ' + newLine
        return output


class PDFBody :
    def __init__(self) :
        self.numObjects = 0 # int
        self.objects = {} # PDFIndirectObjects{}
        self.numStreams = 0 # int
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.numURIs = 0
        self.streams = []
        self.nextOffset = 0
        self.encodedStreams = []
        self.faultyStreams = []
        self.faultyObjects = []
        self.referencedJSObjects = []
        self.containingJS = []
        self.containingURIs = []
        self.suspiciousEvents = {}
        self.suspiciousActions = {}
        self.suspiciousElements = {}
        self.vulns = {}
        self.javascriptCode = []
        self.javascriptCodePerObject = []
        self.URLs = []
        self.uriList = []
        self.uriListPerObject = []
        self.toUpdate = []
        self.xrefStreams = []
        self.objectStreams = []
        self.compressedObjects = []
        self.errors = []

    def addCompressedObject(self, id):
        if id not in self.compressedObjects:
            self.compressedObjects.append(id)

    def addObjectStream(self, id):
        if id not in self.objectStreams:
            self.objectStreams.append(id)

    def addXrefStream(self, id):
        if id not in self.xrefStreams:
            self.xrefStreams.append(id)

    def containsCompressedObjects(self):
        if len(self.compressedObjects) > 0:
            return True
        else:
            return False

    def containsObjectStreams(self):
        if len(self.objectStreams) > 0:
            return True
        else:
            return False

    def containsXrefStreams(self):
        if len(self.xrefStreams) > 0:
            return True
        else:
            return False
            
    def delObject(self, id):
        if id in self.objects:
            indirectObject = self.objects[id]
            return self.deregisterObject(indirectObject)
        else:
            return None

    def deregisterObject(self, pdfIndirectObject):
        type = ''
        errorMessage = ''
        if pdfIndirectObject == None:
            errorMessage = 'Indirect Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        id = pdfIndirectObject.getId()
        if id in self.objects:
            self.objects.pop(id)
        pdfObject = pdfIndirectObject.getObject()
        if pdfObject == None:
            errorMessage = 'Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        objectType = pdfObject.getType()
        self.numObjects -= 1
        if id in self.faultyObjects:
            self.faultyObjects.remove(id)
        self.updateStats(id, pdfObject, delete=True)
        if not pdfObject.updateNeeded:
            if objectType == 'stream':
                self.numStreams -= 1
                if id in self.streams:
                    self.streams.remove(id)
                if pdfObject.isEncoded():
                    if id in self.encodedStreams:
                        self.encodedStreams.remove(id)
                    self.numEncodedStreams -= 1
                    if id in self.faultyStreams:
                        self.faultyStreams.remove(id)
                        self.numDecodingErrors -= 1
                if pdfObject.hasElement('/Type'):
                    typeObject = pdfObject.getElementByName('/Type')
                    if typeObject == None:
                        errorMessage = '/Type element is None'
                        if get_parser_context().force_mode:
                            pdfFile.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                    else:
                        type = typeObject.getValue()
                        if type == '/XRef':
                            if id in self.xrefStreams:
                                self.xrefStreams.remove(id)
                        elif type == '/ObjStm':
                            if id in self.objectStreams:
                                self.objectStreams.remove(id)
                            compressedObjectsDict = pdfObject.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                if compressedId in self.compressedObjects:
                                    self.compressedObjects.remove(compressedId)
                                self.delObject(compressedId)
                            del(compressedObjectsDict)
        objectErrors = pdfObject.getErrors()
        if objectErrors != []:
            index = 0
            errorsAux = list(self.errors)
            while True:
                if objectErrors[0] not in errorsAux:
                    break
                indexAux = errorsAux.index(objectErrors[0])
                if errorsAux[indexAux:indexAux+len(objectErrors)] == objectErrors:
                    for i in range(len(objectErrors)):
                        self.errors.pop(index+indexAux)
                    break
                else:
                    errorsAux = errorsAux[indexAux+len(objectErrors):]
                    index = indexAux+len(objectErrors)
        if type == '':
            type = objectType
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,type)

    def encodeChars(self):
        errorMessage = ''
        for id in self.objects:
            indirectObject = self.objects[id]
            if indirectObject != None:
                object = indirectObject.getObject()
                if object != None:
                    objectType = object.getType()
                    if objectType in ['string','name','array','dictionary','stream']: 
                        ret = object.encodeChars()
                        if ret[0] == -1:
                            errorMessage = ret[1]
                            pdfFile.addError(errorMessage)
                        indirectObject.setObject(object)
                        self.deregisterObject(indirectObject)
                        self.registerObject(indirectObject)
                else:
                    errorMessage = 'Bad object found while encoding strings'
                    pdfFile.addError(errorMessage)
            else:
                errorMessage = 'Bad indirect object found while encoding strings'
                pdfFile.addError(errorMessage)
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')

    def getCompressedObjects(self):
        return self.compressedObjects
    
    def getContainingJS(self):
        return self.containingJS

    def getContainingURIs(self):
        return self.containingURIs

    def getEncodedStreams(self):
        return self.encodedStreams
    
    def getFaultyObjects(self):
        return self.faultyObjects
    
    def getFaultyStreams(self):
        return self.faultyStreams
        
    def getIndirectObject(self, id):
        if id in self.objects:
            return self.objects[id]
        else:
            return None

    def getJSCode(self):
        return self.javascriptCode

    def getJSCodePerObject(self):
        return self.javascriptCodePerObject

    def getNextOffset(self):
        return self.nextOffset

    def getNumDecodingErrors(self):
        return self.numDecodingErrors
        
    def getNumEncodedStreams(self):
        return self.numEncodedStreams
    
    def getNumFaultyObjects(self):
        return len(self.faultyObjects)

    def getNumObjects(self):
        return self.numObjects
    
    def getNumStreams(self):
        return self.numStreams

    def getNumURIs(self):
        return len(self.uriList)

    def getObject(self, id, indirect = False):
        if id in self.objects:
            indirectObject = self.objects[id]
            if indirect:
                return indirectObject
            else:
                return indirectObject.getObject()
        else:
            return None

    def getObjects(self):
        return self.objects    

    def getObjectsByString (self, toSearch) :
        matchedObjects = []
        for indirectObject in list(self.objects.values()):
            if indirectObject.contains(toSearch):
                matchedObjects.append(indirectObject.getId())
        return matchedObjects
    
    def getObjectsIds(self):
        sortedIdsOffsets = []
        sortedIds = []
        for indirectObject in list(self.objects.values()):
            sortedIdsOffsets.append([indirectObject.getId(),indirectObject.getOffset()])
        sortedIdsOffsets = sorted(sortedIdsOffsets, key=lambda x: x[1])
        for i in range(len(sortedIdsOffsets)):
            sortedIds.append(sortedIdsOffsets[i][0])
        return sortedIds

    def getObjectStreams(self):
        return self.objectStreams
    
    def getStreams(self):
        return self.streams

    def getSuspiciousActions(self):
        return self.suspiciousActions
    
    def getSuspiciousElements(self):
        return self.suspiciousElements
    
    def getSuspiciousEvents(self):
        return self.suspiciousEvents

    def getURIs(self):
        return self.uriList

    def getURIsPerObject(self):
        return self.uriListPerObject

    def getURLs(self):
        return self.URLs

    def getVulns(self):
        return self.vulns
        
    def getXrefStreams(self):
        return self.xrefStreams

    def registerObject(self, pdfIndirectObject):
        type = ''
        errorMessage = ''
        if pdfIndirectObject == None:
            errorMessage = 'Indirect Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        id = pdfIndirectObject.getId()
        pdfObject = pdfIndirectObject.getObject()
        if pdfObject == None:
            errorMessage = 'Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        objectType = pdfObject.getType()
        self.numObjects += 1
        if pdfObject.isFaulty():
            self.faultyObjects.append(id)
        ret = self.updateStats(id, pdfObject)
        if ret[0] == -1:
            errorMessage = ret[1]
        if pdfObject.updateNeeded:
            self.toUpdate.append(id)
        else:
            if objectType == 'stream':
                self.numStreams += 1
                self.streams.append(id)
                if pdfObject.isEncoded():
                    self.encodedStreams.append(id)
                    self.numEncodedStreams += 1
                    if pdfObject.isFaultyDecoding():
                        self.faultyStreams.append(id)
                        self.numDecodingErrors += 1
                if pdfObject.hasElement('/Type'):
                    typeObject = pdfObject.getElementByName('/Type')
                    if typeObject == None:
                        errorMessage = '/Type element is None'
                        if get_parser_context().force_mode:
                            pdfFile.addError(errorMessage)
                        else:
                            return (-1,errorMessage)
                    else: 
                        type = typeObject.getValue()
                        if type == '/XRef':
                            self.addXrefStream(id)
                        elif type == '/ObjStm':
                            self.addObjectStream(id)
                            pdfObject.setCompressedObjectId(id)
                            compressedObjectsDict = pdfObject.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                self.addCompressedObject(compressedId)
                                offset = compressedObjectsDict[compressedId][0]
                                compressedObject = compressedObjectsDict[compressedId][1]
                                self.setObject(compressedId, compressedObject, offset)
                            del(compressedObjectsDict)
            elif objectType == 'dictionary':
                self.referencedJSObjects += pdfObject.getReferencedJSObjectIds()
                self.referencedJSObjects = list(set(self.referencedJSObjects))
        pdfIndirectObject.setObject(pdfObject)
        self.objects[id] = pdfIndirectObject
        self.errors += pdfObject.getErrors()
        if type == '':
            type = objectType
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,type)    

    def setNextOffset(self, newOffset):
        self.nextOffset = newOffset

    def setObject(self, id = None, object = None, offset = None, modification = False):
        errorMessage = ''
        if id in self.objects:
            pdfIndirectObject = self.objects[id]
            self.deregisterObject(pdfIndirectObject)
            pdfIndirectObject.setObject(object)
            if offset != None:
                pdfIndirectObject.setOffset(offset)
            size = 12 + 3*len(newLine) + len(str(object.getRawValue())) + len(str(id))
            pdfIndirectObject.setSize(size)
        else:
            if modification:
                errorMessage = 'Object not found'
                if get_parser_context().force_mode:
                    pdfFile.addError(errorMessage)
                else:
                    return (-1,errorMessage)
            if id == None:
                id = self.numObjects+1
            if offset == None:
                offset = self.getNextOffset()
            pdfIndirectObject = PDFIndirectObject()
            pdfIndirectObject.setId(id)
            pdfIndirectObject.setObject(object)
            pdfIndirectObject.setGenerationNumber(0)
            pdfIndirectObject.setOffset(offset)
            size = 12 + 3*len(newLine) + len(str(object.getRawValue())) + len(str(id))
            pdfIndirectObject.setSize(size)
            self.setNextOffset(offset+size)
        ret = self.registerObject(pdfIndirectObject)
        if ret[0] == 0:
            if errorMessage != '':
                return (-1,errorMessage)
            else:
                objectType = ret[1]
                return (0,[id,objectType])
        else:
            return ret


    def setObjects(self, objects):
        self.objects = objects
                
    def updateObjects(self):
        errorMessage = ''
        for id in self.toUpdate:
            updatedElements = {}
            object = self.objects[id].getObject()
            if object == None:
                errorMessage = 'Object is None'
                if get_parser_context().force_mode:
                    pdfFile.addError(errorMessage)
                    continue
                else:
                    return (-1,errorMessage)
            elementsToUpdate = object.getReferencesInElements()
            keys = list(elementsToUpdate.keys())
            for key in keys:
                ref = elementsToUpdate[key]
                refId = ref[0]
                if refId in self.objects:
                    refObject = self.objects[refId].getObject()
                    if refObject == None:
                        errorMessage = 'Referenced object is None'
                        if get_parser_context().force_mode:
                            pdfFile.addError(errorMessage)
                            continue
                        else:
                            return (-1,errorMessage)
                    ref[1] = refObject.getValue()
                    updatedElements[key] = ref
                else:
                    errorMessage = 'Referenced object not found'
                    if get_parser_context().force_mode:
                        pdfFile.addError(errorMessage)
                        continue
                    else:
                        return (-1,errorMessage)
            object.setReferencesInElements(updatedElements)
            object.resolveReferences()
            self.updateStats(id, object)
            if object.getType() == 'stream':
                self.numStreams += 1
                self.streams.append(id)
                if object.isEncoded():
                    self.encodedStreams.append(id)
                    self.numEncodedStreams += 1
                    if object.isFaultyDecoding():
                        self.faultyStreams.append(id)
                        self.numDecodingErrors += 1
                if object.hasElement('/Type'):
                    typeObject = object.getElementByName('/Type')
                    if typeObject == None:
                        errorMessage = 'Referenced element is None'
                        if get_parser_context().force_mode:
                            pdfFile.addError(errorMessage)
                            continue
                        else:
                            return (-1,errorMessage)
                    else: 
                        type = typeObject.getValue()
                        if type == '/XRef':
                            self.addXrefStream(id)
                        elif type == '/ObjStm':
                            self.addObjectStream(id)
                            object.setCompressedObjectId(id)
                            compressedObjectsDict = object.getCompressedObjects()
                            for compressedId in compressedObjectsDict:
                                self.addCompressedObject(compressedId)
                                offset = compressedObjectsDict[compressedId][0]
                                compressedObject = compressedObjectsDict[compressedId][1]
                                self.setObject(compressedId, compressedObject, offset)
                            del(compressedObjectsDict)
        for id in self.referencedJSObjects:
            if id not in self.containingJS:
                object = self.objects[id].getObject()
                if object == None:
                    errorMessage = 'Object is None'
                    if get_parser_context().force_mode:
                        pdfFile.addError(errorMessage)
                        continue
                    else:
                        return (-1,errorMessage)
                object.setReferencedJSObject(True)
                self.updateStats(id, object)
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')
    
    def updateOffsets (self) :
        pass

    def updateStats(self, id, pdfObject, delete=False):
        if pdfObject == None:
            errorMessage = 'Object is None'
            pdfFile.addError(errorMessage)
            return (-1,errorMessage)
        value = pdfObject.getValue()
        for event in monitorizedEvents:
            if value.find(event) != -1:
                printedEvent = event.strip()
                if printedEvent in self.suspiciousEvents:
                    if delete:
                        if id in self.suspiciousEvents[printedEvent]:
                            self.suspiciousEvents[printedEvent].remove(id)
                    elif id not in self.suspiciousEvents[printedEvent]:
                        self.suspiciousEvents[printedEvent].append(id)
                elif not delete:
                    self.suspiciousEvents[printedEvent] = [id]
        for action in monitorizedActions:
            index = value.find(action)
            if index != -1 and (action == '/JS ' or len(value) == index + len(action) or value[index+len(action)] in delimiterChars+spacesChars):
                printedAction = action.strip()
                if printedAction in self.suspiciousActions:
                    if delete:
                        if id in self.suspiciousActions[printedAction]:
                            self.suspiciousActions[printedAction].remove(id)
                    elif id not in self.suspiciousActions[printedAction]:
                        self.suspiciousActions[printedAction].append(id)
                elif not delete:
                    self.suspiciousActions[printedAction] = [id]
        for element in monitorizedElements:
            index = value.find(element)
            if index != -1 and (element == '/EmbeddedFiles ' or len(value) == index + len(element) or value[index+len(element)] in delimiterChars+spacesChars):
                printedElement = element.strip()
                if printedElement in self.suspiciousElements:
                    if delete:
                        if id in self.suspiciousElements[printedElement]:
                            self.suspiciousElements[printedElement].remove(id)
                    elif id not in self.suspiciousElements[printedElement]:
                        self.suspiciousElements[printedElement].append(id)
                elif not delete:
                    self.suspiciousElements[printedElement] = [id]
        if pdfObject.containsJS():
            if delete:
                jsCodeArray = pdfObject.getJSCode()
                if id in self.containingJS:
                    self.containingJS.remove(id)
                    for jsCode in jsCodeArray:
                        if jsCode in self.javascriptCode:
                            self.javascriptCode.remove(jsCode)
                            if [id, jsCode] in self.javascriptCodePerObject:
                                self.javascriptCodePerObject.remove([id, jsCode])
                        for vuln in jsVulns:
                            if jsCode.find(vuln) != -1:
                                if vuln in self.vulns and id in self.vulns[vuln]:
                                    self.vulns[vuln].remove(id)
            else:
                jsCode = pdfObject.getJSCode()
                if id not in self.containingJS:
                    self.containingJS.append(id)
                for js in jsCode:
                    if js not in self.javascriptCode:
                        self.javascriptCode.append(js)
                        if [id, js] not in self.javascriptCodePerObject:
                            self.javascriptCodePerObject.append([id, js])
                for code in jsCode:
                    for vuln in jsVulns:
                        if code.find(vuln) != -1:
                            if vuln in self.vulns:
                                self.vulns[vuln].append(id)
                            else:
                                self.vulns[vuln] = [id]
        if pdfObject.containsURIs():
            uris = pdfObject.getURIs()
            if delete:
                if id in self.containingURIs:
                    self.containingURIs.remove(id)
                    for uri in uris:
                        if uri in self.uriList:
                            self.uriList.remove(uri)
                            if [id, uri] in self.uriListPerObject:
                                self.uriListPerObject.remove([id, uri])
            else:
                if id not in self.containingURIs:
                    self.containingURIs.append(id)
                for uri in uris:
                    self.uriList.append(uri)
                    if [id, uri] not in self.uriListPerObject:
                        self.uriListPerObject.append([id, uri])
        ## Extra checks
        objectType = pdfObject.getType()
        if objectType == 'stream':
            vulnFound = None
            streamContent = pdfObject.getStream()
            if len(streamContent) > 327 and streamContent[236:240] == 'SING' and streamContent[327] != '\0':
                # CVE-2010-2883
                # http://opensource.adobe.com/svn/opensource/tin/src/SING.cpp
                # http://community.websense.com/blogs/securitylabs/archive/2010/09/10/brief-analysis-on-adobe-reader-sing-table-parsing-vulnerability-cve-2010-2883.aspx
                vulnFound = singUniqueName
            elif streamContent.count('AAL/AAAC/wAAAv8A') > 1000:
                # CVE-2013-2729
                # Adobe Reader BMP/RLE heap corruption
                # http://blog.binamuse.com/2013/05/readerbmprle.html
                vulnFound = bmpVuln
            if vulnFound != None:    
                if vulnFound in self.suspiciousElements:
                    if delete:
                        if id in self.suspiciousElements[vulnFound]:
                            self.suspiciousElements[vulnFound].remove(id)
                    elif id not in self.suspiciousElements[vulnFound]:
                        self.suspiciousElements[vulnFound].append(id)
                elif not delete:
                    self.suspiciousElements[vulnFound] = [id]
        return (0,'')                        
    


class PDFTrailer :
    def __init__(self, dict, lastCrossRefSection = '0', streamPresent = False):
        self.errors = []
        self.dict = dict
        self.offset = 0
        self.eofOffset = 0
        self.size = 0
        self.streamObject = None
        self.catalogId = None
        self.numObjects = None
        self.id = None
        self.infoId = None
        self.lastCrossRefSection = int(lastCrossRefSection)
        ret = self.update(streamPresent)
        if ret[0] == -1:
            if get_parser_context().force_mode:
                self.addError(ret[1])
            else:
                raise Exception(ret[1])
        
    def update(self, streamPresent = False):
        errorMessage = ''
        if self.dict == None:
            errorMessage = 'The trailer dictionary is None'
            self.addError(errorMessage)
            return (-1,errorMessage)
        if self.dict.hasElement('/Root'):
            reference = self.dict.getElementByName('/Root')
            if reference != None:
                if reference.getType() == 'reference':
                    self.catalogId = reference.getId()
                else:
                    errorMessage = 'No reference element in /Root'
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
            else:
                errorMessage = 'No reference element in /Root'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        else:
            if not streamPresent:
                errorMessage = 'Missing /Root element'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        if self.dict.hasElement('/Size'):
            size = self.dict.getElementByName('/Size')
            if size != None:
                if size.getType() == 'integer':
                    self.numObjects = size.getRawValue()
                else:
                    errorMessage = 'No integer element in /Size'
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
            else:
                errorMessage = 'No integer element in /Size'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        else:
            if not streamPresent:
                errorMessage = 'Missing /Size element'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        if self.dict.hasElement('/Info'):
            info = self.dict.getElementByName('/Info')
            if info != None:
                if info.getType() == 'reference':
                    self.infoId = info.getId()
                else:
                    errorMessage = 'No reference element in /Info'
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1,errorMessage)
            else:
                errorMessage = 'No reference element in /Info'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1,errorMessage)
        if self.dict.hasElement('/ID'):
            arrayID = self.dict.getElementByName('/ID')
            if arrayID != None:
                if arrayID.getType() == 'array':
                    self.id = arrayID.getRawValue()    
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,'')

    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)
                
    def encodeChars(self):
        ret = self.dict.encodeChars()
        if ret[0] == -1:
            self.addError(ret[1])
        return ret

    def getCatalogId(self):
        return self.catalogId
    
    def getDictEntry(self, name):
        if self.dict.hasElement(name):
            return self.dict.getElementByName(name)
        else:
            return None

    def getEOFOffset(self):
        return self.eofOffset        

    def getErrors(self):
        return self.errors

    def getID(self):
        return self.id
    
    def getInfoId(self):
        return self.infoId

    def getLastCrossRefSection(self):
        return self.lastCrossRefSection
        
    def getNumObjects(self):
        return self.numObjects
    
    def getOffset(self):
        return self.offset
        
    def getPrevCrossRefSection(self):
        return self.dict.getElementByName('/Prev')
        
    def getSize(self):
        return self.size
        
    def getStats(self):
        stats = {}
        if self.offset != -1:
            stats['Offset'] = str(self.offset)
        else:
            stats['Offset'] = None
        stats['Size'] = str(self.size)
        if self.inStream():
            stats['Stream'] = str(self.streamObject)
        else:
            stats['Stream'] = None
        stats['Objects'] = str(self.numObjects)
        if self.dict.hasElement('/Root'):
            stats['Root Object'] = str(self.catalogId)
        else:
            stats['Root Object'] = None
            self.addError('/Root element not found')
        if self.dict.hasElement('/Info'):
            stats['Info Object'] = str(self.infoId)
        else:
            stats['Info Object'] = None
        if self.dict.hasElement('/ID') and self.id != None and self.id != '' and self.id != ' ':
            stats['ID'] = self.id
        else:
            stats['ID'] = None
        if self.dict.hasElement('/Encrypt'):
            if self.getDictEntry('/Encrypt').getType() == 'dictionary':
                stats['Encrypted'] = True
            else:
                stats['Encrypted'] = False
                self.addError('Bad type for /Encrypt element')
        else:
            stats['Encrypted'] = False
        if self.isFaulty():
            stats['Errors'] = str(len(self.errors))
        else:
            stats['Errors'] = None
        return stats

    def getTrailerDictionary(self):
        return self.dict

    def getXrefStreamObject(self):
        return self.streamObject
        
    def inStream(self):
        if self.streamObject != None:
            return True
        else:
            return False

    def isFaulty(self):
        if self.errors == []:
            return False
        else:
            return True
        
    def setCatalogId(self, newId):
        self.catalogId = newId
        
    def setDictEntry(self, entry, value):
        ret = self.dict.setElement(entry,value)
        if ret[0] == -1:
            errorMessage = ret[1]+' in dictionary element'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return ret

    def setEOFOffset(self, offset):
        self.eofOffset = offset
                    
    def setInfoId(self, newId):
        self.infoId = newId

    def setID(self, newId):
        self.id = newId
        
    def setLastCrossRefSection(self, newOffset):
        self.lastCrossRefSection = newOffset

    def setNumObjects(self, newNumObjects):
        self.numObjects = newNumObjects
        try:
            size = PDFNum(str(newNumObjects))
        except:
            errorMessage = 'Error creating PDFNum'
            if get_parser_context().force_mode:
                self.addError(errorMessage)
                size = PDFNum('0')
            else:
                return (-1,errorMessage)
        ret = self.setDictEntry('/Size', size)
        return ret
            
    def setOffset(self, offset):
        self.offset = offset    

    def setPrevCrossRefSection(self, newOffset):
        try:
            prevSectionObject = PDFNum(str(newOffset))
        except:
            errorMessage = 'Error creating PDFNum'
            if get_parser_context().force_mode:
                self.addError(errorMessage)
                prevSectionObject = PDFNum('0')
            else:
                return (-1,errorMessage)
        ret = self.dict.setElement('/Prev', prevSectionObject)
        if ret[0] == -1:
            errorMessage = ret[1]+' in dictionary element'
            self.addError(errorMessage)
            return (-1,errorMessage)
        return ret

    def setSize(self, newSize):
        self.size = newSize
                
    def setTrailerDictionary(self, newDict):
        self.dict = newDict
        ret = self.update()
        return ret

    def setXrefStreamObject(self, id):
        self.streamObject = id
                
    def toFile(self):
        output = ''
        if self.dict.getNumElements() > 0:
            output += 'trailer' + newLine
            output += self.dict.toFile() + newLine
        output += 'startxref' + newLine
        output += str(self.lastCrossRefSection) + newLine
        output += '%%EOF' + newLine
        return output
    

class PDFFile :
    def __init__(self) :
        self.fileName = ''
        self.path = ''
        self.size = 0
        self.md5 = ''
        self.sha1 = ''
        self.sha256 = ''
        self.detectionRate = []
        self.detectionReport = ''
        self.body = [] # PDFBody[]
        self.binary = False
        self.binaryChars = ''
        self.linearized = False
        self.encryptDict = None
        self.encrypted = False
        self.fileId = ''
        self.encryptionAlgorithms = []
        self.encryptionKey = ''
        self.encryptionKeyLength = 128
        self.ownerPass = ''
        self.userPass = ''
        self.JSCode = ''
        self.crossRefTable = [] # PDFCrossRefSection[]
        self.comments = [] # string[]
        self.version = ''
        self.headerOffset = 0
        self.garbageHeader = ''
        self.suspiciousElements = {}
        self.updates = 0
        self.endLine = ''
        self.trailer = [] # PDFTrailer[]
        self.errors = []
        self.numObjects = 0
        self.numStreams = 0
        self.numURIs = 0
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.maxObjectId = 0

    def addBody(self, newBody):
        if newBody != None and isinstance(newBody,PDFBody):
            self.body.append(newBody)
            return (0,'')
        else:
            return (-1,'Bad PDFBody supplied')

    def addCrossRefTableSection(self, newSectionArray):
        if newSectionArray != None and isinstance(newSectionArray,list) and len(newSectionArray) == 2 and (newSectionArray[0] == None or isinstance(newSectionArray[0],PDFCrossRefSection)) and (newSectionArray[1] == None or isinstance(newSectionArray[1],PDFCrossRefSection)):
            self.crossRefTable.append(newSectionArray)
            return (0,'')
        else:
            return (-1,'Bad PDFCrossRefSection array supplied')
    
    def addError(self, errorMessage):
        if errorMessage not in self.errors:
            self.errors.append(errorMessage)

    def addNumDecodingErrors(self, num):
        self.numDecodingErrors += num

    def addNumEncodedStreams(self, num):
        self.numEncodedStreams += num
                    
    def addNumObjects(self, num):
        self.numObjects += num
        
    def addNumStreams(self, num):
        self.numStreams += num

    def addNumURIs(self, num):
        self.numURIs += num

    def addTrailer(self, newTrailerArray):
        if newTrailerArray != None and isinstance(newTrailerArray,list) and len(newTrailerArray) == 2 and (newTrailerArray[0] == None or isinstance(newTrailerArray[0],PDFTrailer)) and (newTrailerArray[1] == None or isinstance(newTrailerArray[1],PDFTrailer)):
            self.trailer.append(newTrailerArray)
            return (0,'')
        else:
            return (-1,'Bad PDFTrailer array supplied')    

    def createObjectStream(self, version = None, id = None, objectIds = []):
        errorMessage = ''
        tmpStreamObjects = ''
        tmpStreamObjectsInfo = ''
        compressedStream = ''
        compressedDict = {}
        firstObjectOffset = ''
        if version == None:
            version = self.updates
        if objectIds == []:
            objectIds = self.body[version].getObjectsIds()
        numObjects = len(objectIds)
        if id == None:
            id = self.maxObjectId + 1
        for compressedId in objectIds:
            object = self.body[version].getObject(compressedId)
            if object == None:
                errorMessage = 'Object '+str(compressedId)+' cannot be compressed: it does not exist'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                    numObjects -= 1
                else:
                    return (-1,errorMessage)
            else:
                objectType = object.getType()
                if objectType == 'stream':
                    errorMessage = 'Stream objects cannot be compressed'
                    self.addError(errorMessage)
                    numObjects -= 1
                else:
                    if objectType == 'dictionary' and object.hasElement('/U') and object.hasElement('/O') and object.hasElement('/R'):
                        errorMessage = 'Encryption dictionaries cannot be compressed'
                        self.addError(errorMessage)
                        numObjects -= 1
                    object.setCompressedIn(id)
                    offset = len(tmpStreamObjects)
                    tmpStreamObjectsInfo += str(compressedId)+' '+str(offset)+' '
                    tmpStreamObjects += object.toFile()
                    ret = self.body[version].setObject(compressedId,object,offset,modification = True)
                    if ret[0] == -1:
                        errorMessage = ret[1]
                        self.addError(ret[1])
        firstObjectOffset = str(len(tmpStreamObjectsInfo))
        compressedStream = tmpStreamObjectsInfo + tmpStreamObjects
        compressedDict = {'/Type':PDFName('ObjStm'),'/N':PDFNum(str(numObjects)),'/First':PDFNum(firstObjectOffset),'/Length':PDFNum(str(len(compressedStream)))}
        try:
            objectStream = PDFObjectStream('',compressedStream,compressedDict,{},{})
        except Exception as e:
            errorMessage = 'Error creating PDFObjectStream'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        # Filters
        filterObject = PDFName('FlateDecode')
        ret = objectStream.setElement('/Filter',filterObject)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        objectStreamOffset = self.body[version].getNextOffset()
        if self.encrypted:
            ret = computeObjectKey(id, 0, self.encryptionKey, self.encryptionKeyLength/8)
            if ret[0] == -1:
                errorMessage = ret[1]
                self.addError(ret[1])
            else:
                key = ret[1]
                ret = objectStream.encrypt(key)
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(ret[1])
        self.body[version].setNextOffset(objectStreamOffset+len(objectStream.getRawValue()))
        self.body[version].setObject(id,objectStream,objectStreamOffset)
        # Xref stream
        ret = self.createXrefStream(version)
        if ret[0] == -1:
            return ret
        xrefStreamId, xrefStream = ret[1]
        xrefStreamOffset = self.body[version].getNextOffset()
        ret = self.body[version].setObject(xrefStreamId,xrefStream,xrefStreamOffset)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        self.binary = True
        self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,id)

    def createXrefStream(self, version, id = None):
        size = 0
        elementsDict = {}
        elementsTrailerDict = {}
        stream = ''
        errorMessage = ''
        indexArray = []
        xrefStream = None
        xrefStreamId = None
        bytesPerFieldArray = []

        if version == None:
            version = self.updates
        # Trailer update
        if len(self.trailer) > version:
            if self.trailer[version][1] != None:
                trailerDict = self.trailer[version][1].getTrailerDictionary()
                if trailerDict != None:
                    elementsTrailerDict = dict(trailerDict.getElements())
                    elementsDict = dict(elementsTrailerDict)
                del(trailerDict)
            if self.trailer[version][0] != None:
                trailerDict = self.trailer[version][0].getTrailerDictionary()
                if trailerDict != None:
                    trailerElementsDict = dict(trailerDict.getElements())
                    if len(trailerElementsDict) > 0:
                        for key in trailerElementsDict:
                            if key not in elementsTrailerDict:
                                elementsTrailerDict[key] = trailerElementsDict[key]
                                elementsDict[key] = trailerElementsDict[key]
                    del(trailerElementsDict)
                del(trailerDict)    
        self.createXrefStreamSection(version)
        if len(self.crossRefTable) <= version:
            errorMessage = 'Cross Reference Table not found'
            self.addError(errorMessage)
            return (-1,errorMessage)
        section = self.crossRefTable[version][1]
        xrefStreamId = section.getXrefStreamObject()
        bytesPerField = section.getBytesPerField()
        for num in bytesPerField:
            try:
                bytesPerFieldArray.append(PDFNum(str(num)))
            except:
                errorMessage = 'Error creating PDFNum in bytesPerField'
                return (-1,errorMessage)
        subsectionsNumber = section.getSubsectionsNumber()
        subsections = section.getSubsectionsArray()
        for subsection in subsections:
            firstObject = subsection.getFirstObject()
            numObjects = subsection.getNumObjects()
            indexArray.append(PDFNum(str(firstObject)))
            indexArray.append(PDFNum(str(numObjects)))
            entries = subsection.getEntries()
            for entry in entries:
                ret = entry.getEntryBytes(bytesPerField)
                if ret[0] == -1:
                    self.addError(ret[1])
                    return (-1,ret[1])
                stream += ret[1]
            if size < firstObject + numObjects:
                size = firstObject + numObjects
        elementsDict['/Type'] = PDFName('XRef')
        elementsDict['/Size'] = PDFNum(str(size))
        elementsTrailerDict['/Size'] = PDFNum(str(size))
        elementsDict['/Index'] = PDFArray('',indexArray)
        elementsDict['/W'] = PDFArray('',bytesPerFieldArray)        
        elementsDict['/Length'] = PDFNum(str(len(stream)))
        try:
            xrefStream = PDFStream('',stream,elementsDict,{})
        except Exception as e:
            errorMessage = 'Error creating PDFStream'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        # Filters
        filterObject = PDFName('FlateDecode')
        if id != None:
            xrefStreamObject = self.getObject(id, version)
            if xrefStreamObject != None:
                filterObject = xrefStreamObject.getElementByName('/Filter')
        ret = xrefStream.setElement('/Filter',filterObject)
        if ret[0] == -1:
            errorMessage = ret[1]
            self.addError(ret[1])
        try:
            trailerStream = PDFTrailer(PDFDictionary(elements=elementsTrailerDict))
        except Exception as e:
            errorMessage = 'Error creating PDFTrailer'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        trailerStream.setXrefStreamObject(xrefStreamId)
        try:
            trailerSection = PDFTrailer(PDFDictionary(elements=dict(elementsTrailerDict)))#PDFDictionary())
        except Exception as e:
            errorMessage = 'Error creating PDFTrailer'
            if e.message != '':
                errorMessage += ': '+e.message
            self.addError(errorMessage)
            return (-1,errorMessage)
        self.trailer[version] = [trailerSection,trailerStream]
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,[xrefStreamId,xrefStream])
    
    def createXrefStreamSection(self, version = None):
        lastId = 0
        lastFreeObject = 0
        errorMessage = ''
        xrefStreamId = None
        xrefEntries = [PDFCrossRefEntry(0,65535,0)]
        if version == None:
            version = self.updates
        actualStream = self.crossRefTable[version][1]
        if actualStream != None:
             xrefStreamId = actualStream.getXrefStreamObject()
        sortedObjectsByOffset = self.body[version].getObjectsIds()
        sortedObjectsIds = sorted(sortedObjectsByOffset, key=lambda x: int(x))
        indirectObjects = self.body[version].getObjects()
        for id in sortedObjectsIds:
            while id != lastId+1:
                lastFreeEntry = xrefEntries[lastFreeObject]
                lastFreeEntry.setNextObject(lastId+1)
                xrefEntries[lastFreeObject] = lastFreeEntry
                lastFreeObject = lastId+1
                lastId += 1
                xrefEntries.append(PDFCrossRefEntry(0,65535,0))
            indirectObject = indirectObjects[id]
            if indirectObject != None:
                object = indirectObject.getObject()
                if object != None:
                    if object.isCompressed():
                        objectStreamId = object.getCompressedIn()
                        objectStream = self.body[version].getObject(objectStreamId)
                        index = objectStream.getObjectIndex(id)
                        if index == None:
                            errorMessage = 'Compressed object not found in object stream'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1,errorMessage)
                        entry = PDFCrossRefEntry(objectStreamId,index,2)
                    else:
                        offset = indirectObject.getOffset()
                        entry = PDFCrossRefEntry(offset,0,1)
                    xrefEntries.append(entry)
                    lastId = id
        if actualStream == None:
            offset += len(str(object.getRawValue()))
            xrefEntries.append(PDFCrossRefEntry(offset,0,1))
            lastId += 1
            xrefStreamId = lastId
        subsection = PDFCrossRefSubSection(0,lastId+1,xrefEntries)
        xrefSection = PDFCrossRefSection()
        xrefSection.addSubsection(subsection)
        xrefSection.setXrefStreamObject(xrefStreamId)
        xrefSection.setBytesPerField([1,2,2])
        self.crossRefTable[version] = [None,xrefSection]
        if errorMessage != '':
            return (-1,errorMessage)
        return (0,lastId)

    def decrypt(self, password=''):
        badPassword = False
        fatalError = False
        errorMessage = ''
        passType = None
        encryptionAlgorithms = []
        algorithm = None
        stmAlgorithm = None
        strAlgorithm = None
        embedAlgorithm = None
        computedUserPass = ''
        dictO = '' 
        dictU = ''
        perm = 0
        revision = 0
        fileId = self.getFileId()
        self.removeError(errorType = 'Decryption error')
        if self.encryptDict == None or self.encryptDict[1] == []:
            errorMessage = 'Decryption error: /Encrypt dictionary not found!!'
            if get_parser_context().force_mode:
                self.addError(errorMessage)
            else:
                return (-1,errorMessage)
        # Getting /Encrypt elements
        encDict = self.encryptDict[1]
        # Filter
        if '/Filter' in encDict:
            filter = encDict['/Filter']
            if filter != None and filter.getType() == 'name':
                filter = filter.getValue()
                if filter != '/Standard':
                    errorMessage = 'Decryption error: Filter not supported!!'
                    if get_parser_context().force_mode:
                        fatalError = True
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            else:
                errorMessage = 'Decryption error: Bad format for /Filter!!'
                if get_parser_context().force_mode:
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Filter not found!!'
            if get_parser_context().force_mode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Algorithm version
        if '/V' in encDict:
            algVersion = encDict['/V']
            if algVersion != None and algVersion.getType() == 'integer':
                algVersion = algVersion.getRawValue()
                if algVersion == 4 or algVersion == 5:
                    stmAlgorithm = ['Identity',40]
                    strAlgorithm = ['Identity',40]
                    embedAlgorithm = ['Identity',40]
                    algorithms = {}
                    if '/CF' in encDict:
                        cfDict = encDict['/CF']
                        if cfDict != None and cfDict.getType() == 'dictionary':
                            cfDict = cfDict.getElements()
                            for cryptFilter in cfDict:
                                cryptFilterDict = cfDict[cryptFilter]
                                if cryptFilterDict != None and cryptFilterDict.getType() == 'dictionary':
                                    algorithms[cryptFilter] = []
                                    defaultKeyLength = 40
                                    cfmValue = ''
                                    cryptFilterDict = cryptFilterDict.getElements()
                                    if '/CFM' in cryptFilterDict:
                                        cfmValue = cryptFilterDict['/CFM']
                                        if cfmValue != None and cfmValue.getType() == 'name':
                                            cfmValue = cfmValue.getValue()
                                            if cfmValue == 'None':
                                                algorithms[cryptFilter].append('Identity')
                                            elif cfmValue == '/V2':
                                                algorithms[cryptFilter].append('RC4')
                                            elif cfmValue == '/AESV2':
                                                algorithms[cryptFilter].append('AES')
                                                defaultKeyLength = 128
                                            elif cfmValue == '/AESV3':
                                                algorithms[cryptFilter].append('AES')
                                                defaultKeyLength = 256
                                            else:
                                                errorMessage = 'Decryption error: Unsupported encryption!!'
                                                if get_parser_context().force_mode:
                                                    self.addError(errorMessage)
                                                else:
                                                    return (-1, errorMessage)
                                        else:
                                            errorMessage = 'Decryption error: Bad format for /CFM!!'
                                            if get_parser_context().force_mode:
                                                cfmValue = ''
                                                self.addError(errorMessage)
                                            else:
                                                return (-1, errorMessage)
                                    if '/Length' in cryptFilterDict and cfmValue != '/AESV3':
                                        # Length is key length in bits
                                        keyLength = cryptFilterDict['/Length']
                                        if keyLength != None and keyLength.getType() == 'integer':
                                            keyLength = keyLength.getRawValue()
                                            if keyLength % 8 != 0:
                                                keyLength = defaultKeyLength
                                                self.addError('Decryption error: Key length not valid!!')
                                            # Check if the length element contains bytes instead of bits as usual
                                            if keyLength < 40:
                                                keyLength *= 8
                                        else:
                                            keyLength = defaultKeyLength
                                            self.addError('Decryption error: Bad format for /Length!!')
                                    else:
                                        keyLength = defaultKeyLength
                                    algorithms[cryptFilter].append(keyLength)
                        else:
                            errorMessage = 'Decryption error: Bad format for /CF!!'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if '/StmF' in encDict:
                        stmF = encDict['/StmF']
                        if stmF != None and stmF.getType() == 'name':
                            stmF = stmF.getValue()
                            if stmF in algorithms:
                                stmAlgorithm = algorithms[stmF]
                        else:
                            errorMessage = 'Decryption error: Bad format for /StmF!!'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if '/StrF' in encDict:
                        strF = encDict['/StrF']
                        if strF != None and strF.getType() == 'name':
                            strF = strF.getValue()
                            if strF in algorithms:
                                strAlgorithm = algorithms[strF]
                        else:
                            errorMessage = 'Decryption error: Bad format for /StrF!!'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    if '/EEF' in encDict:
                        eeF = encDict['/EEF']
                        if eeF != None and eeF.getType() == 'name':
                            eeF = eeF.getValue()
                            if eeF in algorithms:
                                embedAlgorithm = algorithms[eeF]
                        else:
                            embedAlgorithm = stmAlgorithm
                            errorMessage = 'Decryption error: Bad format for /EEF!!'
                            if get_parser_context().force_mode:
                                self.addError(errorMessage)
                            else:
                                return (-1, errorMessage)
                    else:
                        embedAlgorithm = stmAlgorithm
                    if stmAlgorithm not in encryptionAlgorithms:
                        encryptionAlgorithms.append(stmAlgorithm)                        
                    if strAlgorithm not in encryptionAlgorithms:
                        encryptionAlgorithms.append(strAlgorithm)
                    if embedAlgorithm not in encryptionAlgorithms and embedAlgorithm != ['Identity',40]: # Not showing default embedAlgorithm
                        encryptionAlgorithms.append(embedAlgorithm) 
            else:
                errorMessage = 'Decryption error: Bad format for /V!!'
                if get_parser_context().force_mode:
                    algVersion = 0
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Algorithm version not found!!'
            if get_parser_context().force_mode:
                algVersion = 0
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        
        # Key length
        if '/Length' in encDict:
            keyLength = encDict['/Length']
            if keyLength != None and keyLength.getType() == 'integer':
                keyLength = keyLength.getRawValue()
                if keyLength % 8 != 0:
                    keyLength = 40
                    self.addError('Decryption error: Key length not valid!!')
            else:
                keyLength = 40
                self.addError('Decryption error: Bad format for /Length!!')
        else:
            keyLength = 40
        
        # Setting algorithms
        if algVersion == 1 or algVersion == 2:
            algorithm = ['RC4',keyLength]
            stmAlgorithm = strAlgorithm = embedAlgorithm = algorithm
        elif algVersion == 3:
            errorMessage = 'Decryption error: Algorithm not supported!!'
            if get_parser_context().force_mode:
                algorithm = ['Unpublished',keyLength]
                stmAlgorithm = strAlgorithm = embedAlgorithm = algorithm
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        elif algVersion == 5:
            algorithm = ['AES',256]
        if algorithm != None and algorithm not in encryptionAlgorithms:
            encryptionAlgorithms.append(algorithm)
        self.setEncryptionAlgorithms(encryptionAlgorithms)
        
        # Standard encryption: /R /P /O /U
        # Revision
        if '/R' in encDict:
            revision = encDict['/R']
            if revision != None and revision.getType() == 'integer':
                revision = revision.getRawValue()
                if revision < 2 or revision > 5:
                    errorMessage = 'Decryption error: Algorithm revision not supported!!'
                    if get_parser_context().force_mode:
                        fatalError = True
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            else:
                errorMessage = 'Decryption error: Bad format for /R!!'
                if get_parser_context().force_mode:
                    revision = 0
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Algorithm revision not found!!'
            if get_parser_context().force_mode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Permission
        if '/P' in encDict:
            perm = encDict['/P']
            if perm != None and perm.getType() == 'integer':
                perm = perm.getRawValue()
            else:
                errorMessage = 'Decryption error: Bad format for /P!!'
                if get_parser_context().force_mode:
                    perm = 0
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Permission number not found!!'
            if get_parser_context().force_mode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Owner pass
        if '/O' in encDict:
            dictO = encDict['/O']
            if dictO != None and dictO.getType() in ['string','hexstring']:
                dictO = dictO.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /O!!'
                if get_parser_context().force_mode:
                    dictO = ''
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: Owner password not found!!'
            if get_parser_context().force_mode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # Owner encrypted string
        if '/OE' in encDict:
            dictOE = encDict['/OE']
            if dictOE != None and dictOE.getType() in ['string','hexstring']:
                dictOE = dictOE.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /OE!!'
                if get_parser_context().force_mode:
                    dictOE = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            dictOE = ''
            if revision == 5:
                errorMessage = 'Decryption error: /OE not found!!'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        # User pass
        if '/U' in encDict:
            dictU = encDict['/U']
            if dictU != None and dictU.getType() in ['string','hexstring']:
                dictU = dictU.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /U!!'
                if get_parser_context().force_mode:
                    dictU = ''
                    fatalError = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            errorMessage = 'Decryption error: User password not found!!'
            if get_parser_context().force_mode:
                fatalError = True
                self.addError(errorMessage)
            else:
                return (-1, errorMessage)
        # User encrypted string
        if '/UE' in encDict:
            dictUE = encDict['/UE']
            if dictUE != None and dictUE.getType() in ['string','hexstring']:
                dictUE = dictUE.getValue()
            else:
                errorMessage = 'Decryption error: Bad format for /UE!!'
                if get_parser_context().force_mode:
                    dictUE = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            dictUE = ''
            if revision == 5:
                errorMessage = 'Decryption error: /UE not found!!'
                if get_parser_context().force_mode:
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        # Metadata encryption
        if '/EncryptMetadata' in encDict:
            encryptMetadata = encDict['/EncryptMetadata']
            if encryptMetadata != None and encryptMetadata.getType() == 'bool':
                encryptMetadata = encryptMetadata.getValue() != 'false'
            else:
                errorMessage = 'Decryption error: Bad format for /EncryptMetadata!!'
                if get_parser_context().force_mode:
                    encryptMetadata = True
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
        else:
            encryptMetadata = True
        if not fatalError:
            # Checking user password
            if revision != 5:
                ret = computeUserPass(password, dictO, fileId, perm, keyLength, revision, encryptMetadata)
                if ret[0] != -1:
                    computedUserPass = ret[1]
                else:
                    errorMessage = ret[1]
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
            if isUserPass(password, computedUserPass, dictU, revision):
                passType = 'USER'
            elif isOwnerPass(password, dictO, dictU, computedUserPass, keyLength, revision):
                passType = 'OWNER'
            else:
                badPassword = True
                if password == '':
                    errorMessage = 'Decryption error: Default user password not working here!!'
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
                else:
                    errorMessage = 'Decryption error: User password not working here!!'
                    if get_parser_context().force_mode:
                        self.addError(errorMessage)
                    else:
                        return (-1, errorMessage)
        self.setOwnerPass(dictO)
        self.setUserPass(dictU)
        if not fatalError and not badPassword:
            ret = computeEncryptionKey(password, dictO, dictU, dictOE, dictUE, fileId, perm, keyLength, revision, encryptMetadata, passType)
            if ret[0] != -1:
                encryptionKey = ret[1]
            else:
                errorMessage = ret[1]
                if get_parser_context().force_mode:
                    encryptionKey = ''
                    self.addError(errorMessage)
                else:
                    return (-1, errorMessage)
            self.setEncryptionKey(encryptionKey)
            self.setEncryptionKeyLength(keyLength)
            # Computing objects passwords and decryption
            numKeyBytes = self.encryptionKeyLength/8
            for v in range(self.updates+1):
                indirectObjectsIds = list(set(self.body[v].getObjectsIds()))
                for id in indirectObjectsIds:
                    indirectObject = self.body[v].getObject(id, indirect = True)
                    if indirectObject != None:
                        generationNum = indirectObject.getGenerationNumber()
                        object = indirectObject.getObject()
                        if object != None and not object.isCompressed():
                            objectType = object.getType()
                            if objectType in ['string', 'hexstring', 'array', 'dictionary'] or \
                                    (objectType == 'stream' and (object.getElement('/Type') is None or
                                    (object.getElement('/Type').getValue() not in ['/XRef', '/Metadata'] or
                                    (object.getElement('/Type').getValue() == '/Metadata' and encryptMetadata)))):
                                key = self.encryptionKey
                                # Removing already set global stats before modifying the object contents
                                self.body[v].updateStats(id, object, delete=True)
                                # Computing keys and decrypting objects
                                if objectType in ['string', 'hexstring', 'array', 'dictionary']:
                                    if revision < 5:
                                        ret = computeObjectKey(id, generationNum, self.encryptionKey, numKeyBytes, strAlgorithm[0])
                                        if ret[0] == -1:
                                            errorMessage = ret[1]
                                            self.addError(ret[1])
                                        else:
                                            key = ret[1]
                                    ret = object.decrypt(key, strAlgorithm[0])
                                else:
                                    if object.getElement('/Type') != None and object.getElement('/Type').getValue() == '/EmbeddedFile':
                                        if revision < 5:
                                            ret = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes,embedAlgorithm[0])
                                            if ret[0] == -1:
                                                errorMessage = ret[1]
                                                self.addError(ret[1])
                                            else:
                                                key = ret[1]
                                        altAlgorithm = embedAlgorithm[0]
                                    else:
                                        if revision < 5:
                                            ret = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes,stmAlgorithm[0])
                                            if ret[0] == -1:
                                                errorMessage = ret[1]
                                                self.addError(ret[1])
                                            else:
                                                key = ret[1]
                                        altAlgorithm = stmAlgorithm[0]
                                    ret = object.decrypt(key, strAlgorithm[0], altAlgorithm)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
                                ret = self.body[v].setObject(id, object)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')

    def deleteObject (self, id) :
        # Remove references too 
        pass
    
    def encodeChars(self):
        errorMessage = ''
        for i in range(self.updates+1):
            ret = self.body[i].encodeChars()
            if ret[0] == -1:
                errorMessage = ret[1]
                self.addError(errorMessage)
            trailerArray = self.trailer[i]
            if trailerArray[0] != None:
                ret = trailerArray[0].encodeChars()
                if ret[0] == -1:
                    errorMessage = ret[1]
                    self.addError(errorMessage)
                self.trailer[i] = trailerArray
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')
    
    def encrypt(self, password = ''):
        #TODO: AESV2 and V3
        errorMessage = ''
        encryptDictId = None
        encryptMetadata = True
        permissionNum = 1073741823
        dictOE = ''
        dictUE = ''
        ret = self.getTrailer()
        if ret != None:
            trailer,trailerStream = ret[1]
            if trailerStream != None:
                encryptDict = trailerStream.getDictEntry('/Encrypt')
                if encryptDict != None:
                    encryptDictType = encryptDict.getType()
                    if encryptDictType == 'reference':
                        encryptDictId = encryptDict.getId()
                fileId = self.getMD5()
                if fileId == '':
                    fileId = hashlib.md5(str(random.random())).hexdigest()
                md5Object = PDFString(fileId)
                fileIdArray = PDFArray(elements=[md5Object,md5Object])
                trailerStream.setDictEntry('/ID',fileIdArray)
                self.setTrailer([trailer,trailerStream])
            else:
                encryptDict = trailer.getDictEntry('/Encrypt')
                if encryptDict != None:
                    encryptDictType = encryptDict.getType()
                    if encryptDictType == 'reference':
                        encryptDictId = encryptDict.getId()
                fileId = self.getMD5()
                if fileId == '':
                    fileId = hashlib.md5(str(random.random())).hexdigest()
                md5Object = PDFString(fileId)
                fileIdArray = PDFArray(elements=[md5Object,md5Object])
                trailer.setDictEntry('/ID',fileIdArray)
                self.setTrailer([trailer,trailerStream])
                                
            ret = computeOwnerPass(password,password,128,revision = 3)
            if ret[0] != -1:
                dictO = ret[1]
            else:
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                else:
                    return (-1,ret[1])
            self.setOwnerPass(dictO)
            ret = computeUserPass(password,dictO,fileId,permissionNum,128,revision = 3)
            if ret[0] != -1:
                dictU = ret[1]
            else:
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                else:
                    return (-1,ret[1])
            self.setUserPass(dictU)
            ret = computeEncryptionKey(password, dictO, dictU, dictOE, dictUE, fileId, permissionNum, 128, revision = 3, encryptMetadata = encryptMetadata, passwordType = 'USER')
            if ret[0] != -1:
                encryptionKey = ret[1]
            else:
                encryptionKey = ''
                if get_parser_context().force_mode:
                    self.addError(ret[1])
                else:
                    return (-1,ret[1])
            self.setEncryptionKey(encryptionKey)
            self.setEncryptionKeyLength(128)
            encryptDict = PDFDictionary(elements = {'/V':PDFNum('2'),'/Length':PDFNum('128'),'/Filter':PDFName('Standard'),
                                                                                        '/R':PDFNum('3'),'/P':PDFNum(str(permissionNum)),'/O':PDFString(dictO),'/U':PDFString(dictU)})
            if encryptDictId != None:
                ret = self.setObject(encryptDictId,encryptDict)
                if ret[0] == -1:
                    errorMessage = '/Encrypt dictionary has not been created/modified'
                    self.addError(errorMessage)
                    return (-1, errorMessage)
            else:
                if trailerStream != None:
                    trailerStream.setDictEntry('/Encrypt',encryptDict)
                else:
                    trailer.setDictEntry('/Encrypt',encryptDict)
                self.setTrailer([trailer,trailerStream])
    
            numKeyBytes = self.encryptionKeyLength/8
            for v in range(self.updates+1):
                indirectObjects = self.body[v].getObjects()
                for id in indirectObjects:
                    indirectObject = indirectObjects[id]
                    if indirectObject != None:
                        generationNum = indirectObject.getGenerationNumber()
                        object = indirectObject.getObject()
                        if object != None and not object.isCompressed():
                            objectType = object.getType()
                            if objectType in ['string','hexstring','array','dictionary'] or (objectType == 'stream' and (object.getElement('/Type') == None or (object.getElement('/Type').getValue() not in ['/XRef','/Metadata'] or (object.getElement('/Type').getValue() == '/Metadata' and encryptMetadata)))):
                                ret = computeObjectKey(id,generationNum,self.encryptionKey,numKeyBytes)
                                if ret[0] == -1:
                                    errorMessage = ret[1]
                                    self.addError(ret[1])
                                else:
                                    key = ret[1]
                                    ret = object.encrypt(key)
                                    if ret[0] == -1:
                                        errorMessage = ret[1]
                                        self.addError(ret[1])
                                    ret = self.body[v].setObject(id,object)
                                    if ret[0] == -1:
                                        errorMessage = ret[1]
                                        self.addError(ret[1])
        else:
            errorMessage = 'Trailer not found'
            self.addError(errorMessage)
        if errorMessage != '':
            return (-1, errorMessage)
        self.setEncrypted(True)
        return (0,'')                
    
    def getBasicMetadata(self, version):
        basicMetadata = {}
        
        # Getting creation information
        infoObject = self.getInfoObject(version)
        if infoObject != None:
            author = infoObject.getElementByName('/Author')
            if author != None and author != []:
                basicMetadata['author'] = author.getValue()
            creator = infoObject.getElementByName('/Creator')
            if creator != None and creator != []:
                basicMetadata['creator'] = creator.getValue()
            producer = infoObject.getElementByName('/Producer')
            if producer != None and producer != []:
                basicMetadata['producer'] = producer.getValue()
            creationDate = infoObject.getElementByName('/CreationDate')
            if creationDate != None and creationDate != []:
                basicMetadata['creation'] = creationDate.getValue()
        if 'author' not in basicMetadata:
            ids = self.getObjectsByString('<dc:creator>',version)
            if ids != None and ids != []:
                for id in ids:
                    author = self.getMetadataElement(id, version, 'dc:creator')
                    if author != None:
                        basicMetadata['author'] = author
                        break
        if 'creator' not in basicMetadata:
            ids = self.getObjectsByString('<xap:CreatorTool>',version)
            if ids != None and ids != []:
                for id in ids:
                    creator = self.getMetadataElement(id, version, 'xap:CreatorTool')
                    if creator != None:
                        basicMetadata['creator'] = creator
                        break
        if 'creator' not in basicMetadata:
            ids = self.getObjectsByString('<xmp:CreatorTool>',version)
            if ids != None and ids != []:
                for id in ids:
                    creator = self.getMetadataElement(id, version, 'xmp:CreatorTool')
                    if creator != None:
                        basicMetadata['creator'] = creator
                        break
        if 'producer' not in basicMetadata:
            ids = self.getObjectsByString('<pdf:Producer>',version)
            if ids != None and ids != []:
                for id in ids:
                    producer = self.getMetadataElement(id, version, 'pdf:Producer')
                    if producer != None:
                        basicMetadata['producer'] = producer
                        break
        if 'creation' not in basicMetadata:
            ids = self.getObjectsByString('<xap:CreateDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    creation = self.getMetadataElement(id, version, 'xap:CreateDate')
                    if creation != None:
                        basicMetadata['creation'] = creation
                        break
        if 'creation' not in basicMetadata:
            ids = self.getObjectsByString('<xmp:CreateDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    creation = self.getMetadataElement(id, version, 'xmp:CreateDate')
                    if creation != None:
                        basicMetadata['creation'] = creation
                        break
        if 'modification' not in basicMetadata:
            ids = self.getObjectsByString('<xap:ModifyDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    modification = self.getMetadataElement(id, version, 'xap:ModifyDate')
                    if modification != None:
                        basicMetadata['modification'] = modification
                        break
        if 'modification' not in basicMetadata:
            ids = self.getObjectsByString('<xmp:ModifyDate>',version)
            if ids != None and ids != []:
                for id in ids:
                    modification = self.getMetadataElement(id, version, 'xmp:ModifyDate')
                    if modification != None:
                        basicMetadata['modification'] = modification
                        break
        return basicMetadata
    
    def getCatalogObject(self, version=None, indirect=False):
        if version == None:
            catalogObjects = []
            catalogIds = self.getCatalogObjectId()
            for i in range(len(catalogIds)):
                id = catalogIds[i]
                if id != None:
                    catalogObject = self.getObject(id, i, indirect)
                    catalogObjects.append(catalogObject)
                else:
                    catalogObjects.append(None)
            return catalogObjects
        else:
            catalogId = self.getCatalogObjectId(version)
            if catalogId != None:
                catalogObject = self.getObject(catalogId, version, indirect)
                return catalogObject
            else:
                return None

    def getCatalogObjectId(self, version = None):
        if version == None:
            catalogIds = []
            for v in range(self.updates+1):
                catalogId = None
                trailer, streamTrailer = self.trailer[v]
                if trailer != None:
                    catalogId = trailer.getCatalogId()
                if catalogId == None and streamTrailer != None:
                    catalogId = streamTrailer.getCatalogId()
                catalogIds.append(catalogId)
            return catalogIds
        else:
            catalogId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer != None:
                catalogId = trailer.getCatalogId()
            if catalogId == None and streamTrailer != None:
                catalogId = streamTrailer.getCatalogId()
            return catalogId

    def getChangeLog (self, version = None) :
        lastVersionObjects = []
        actualVersionObjects = []
        addedObjects = []
        removedObjects = []
        modifiedObjects = []
        notMatchingObjects = []
        changes = []
        if version == None:
            version = self.updates + 1
        else:
            version += 1
        for i in range(version):
            actualVersionObjects = self.body[i].getObjectsIds()
            if i != 0:
                xrefNewObjects = []
                xrefFreeObjects = []
                crossRefSection = self.crossRefTable[i][0]
                crossRefStreamSection = self.crossRefTable[i][1]
                if crossRefSection != None:
                    xrefNewObjects += crossRefSection.getNewObjectIds()
                    xrefFreeObjects += crossRefSection.getFreeObjectIds()
                if crossRefStreamSection != None:
                    xrefNewObjects += crossRefStreamSection.getNewObjectIds()
                    xrefFreeObjects += crossRefStreamSection.getFreeObjectIds()
                for id in actualVersionObjects:
                    if id not in lastVersionObjects:
                        addedObjects.append(id)
                        lastVersionObjects.append(id)
                    else:
                        modifiedObjects.append(id)
                    if id not in xrefNewObjects or id in xrefFreeObjects:
                        notMatchingObjects.append(id)
                for id in lastVersionObjects:
                    if id not in actualVersionObjects:
                        if id in xrefFreeObjects:
                            removedObjects.append(id)
                            lastVersionObjects.remove(id)
                        if id in xrefNewObjects:
                            notMatchingObjects.append(id)
                changes.append([addedObjects,modifiedObjects,removedObjects,notMatchingObjects])
                addedObjects = []
                removedObjects = []
                modifiedObjects = []
                notMatchingObjects = []
            else:
                lastVersionObjects = actualVersionObjects
        return changes

    def getDetectionRate(self):
        return self.detectionRate

    def getDetectionReport(self):
        return self.detectionReport

    def getEndLine(self):
        return self.endLine
        
    def getEncryptDict(self):
        return self.encryptDict
    
    def getEncryptionAlgorithms(self):
        return self.encryptionAlgorithms
        
    def getEncryptionKey(self):
        return self.encryptionKey
        
    def getEncryptionKeyLength(self):
        return self.encryptionKeyLength
    
    def getErrors(self):
        return self.errors

    def getFileId(self):
        return self.fileId    

    def getFileName(self):
        return self.fileName
    
    def getGarbageHeader(self):
        return self.garbageHeader
    
    def getHeaderOffset(self):
        return self.headerOffset

    def getInfoObject(self, version=None, indirect=False):
        if version is None:
            infoObjects = []
            infoIds = self.getInfoObjectId()
            for i in range(len(infoIds)):
                id = infoIds[i]
                if id is not None:
                    infoObject = self.getObject(id, i, indirect)
                    infoObjects.append(infoObject)
                else:
                    infoObjects.append(None)
            return infoObjects
        else:
            infoId = self.getInfoObjectId(version)
            if infoId is not None:
                infoObject = self.getObject(infoId, version, indirect)
                if infoObject is None and version == 0 and self.getLinearized():
                    # Linearized documents can store Info object in the next update
                    infoObject = self.getObject(infoId, None, indirect)
                    return infoObject
                return infoObject
            else:
                return None

    def getInfoObjectId(self, version = None):
        if version == None:
            infoIds = []
            for v in range(self.updates+1):
                infoId = None
                trailer, streamTrailer = self.trailer[v]
                if trailer != None:
                    infoId = trailer.getInfoId()
                if infoId == None and streamTrailer != None:
                    infoId = streamTrailer.getInfoId()
                infoIds.append(infoId)
            else:
                return infoIds
        else:
            infoId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer != None:
                infoId = trailer.getInfoId()
            if infoId == None and streamTrailer != None:
                infoId = streamTrailer.getInfoId()
            return infoId
            
    def getJavascriptCode(self, version=None, perObject=False):
        jsCode = []
        if version is None:
            for version in range(self.updates+1):
                if perObject:
                    jsCode.append(self.body[version].getJSCodePerObject())
                else:
                    jsCode.append(self.body[version].getJSCode())
        else:
            if version <= self.updates and not version < 0:
                if perObject:
                    jsCode.append(self.body[version].getJSCodePerObject())
                else:
                    jsCode.append(self.body[version].getJSCode())
        return jsCode
    
    def getLinearized(self):
        return self.linearized

    def getMD5(self):
        return self.md5
    
    def getMetadata (self, version = None):
        matchingObjects = self.getObjectsByString('/Metadata', version)
        return matchingObjects
    
    def getMetadataElement(self, objectId, version, element):    
        metadataObject = self.getObject(objectId,version)
        if metadataObject != None:
            if metadataObject.getType() == 'stream': 
                stream = metadataObject.getStream()
                matches = re.findall(r'<'+element+'>(.*)</'+element+'>',stream)
                if matches != []:
                    return matches[0]
                else:
                    return None
            else:
                return None
        else:
            return None

    def getNumUpdates(self):
        return self.updates
            
    def getObject (self, id, version = None, indirect = False) :
        ''' 
            Returns the specified object
        '''
        if version == None:
            for i in range(self.updates,-1,-1):
                if indirect:
                    object = self.body[i].getIndirectObject(id)
                else:
                    object = self.body[i].getObject(id)
                if object == None:
                    continue
                else:
                    return object
            else:
                return None
        else:
            if version > self.updates or version < 0:
                return None
            if indirect:
                return self.body[version].getIndirectObject(id)
            else:
                return self.body[version].getObject(id)    

    def getObjectsByString (self, toSearch, version = None) :
        ''' Returns the object containing the specified string. '''
        matchedObjects = []
        if version == None:
            for i in range(self.updates + 1):
                matchedObjects.append(self.body[i].getObjectsByString(toSearch))
            return matchedObjects
        else:
            if version > self.updates or version < 0:
                return None 
            return self.body[version].getObjectsByString(toSearch)
        
    def getOffsets(self, version = None):
        offsetsArray = []
        
        if version == None:
            versions = list(range(self.updates+1))
        else:
            versions = [version]
            
        for version in versions:
            offsets = {}
            trailer = None
            xref = None
            objectStreamsOffsets = {}
            indirectObjects = self.body[version].getObjects()
            sortedObjectsIds = self.body[version].getObjectsIds()
            compressedObjects = self.body[version].getCompressedObjects()
            objectStreams = self.body[version].getObjectStreams()
            ret = self.getXrefSection(version)
            if ret != None:
                xref, streamXref = ret[1]
            ret = self.getTrailer(version)
            if ret != None:
                trailer, streamTrailer = ret[1]
            if objectStreams != []:
                for objStream in objectStreams:
                    if objStream in indirectObjects:
                        indirectObject = indirectObjects[objStream]
                        if indirectObject != None:
                            objectStreamsOffsets[objStream] = indirectObject.getOffset()
            if version == 0:
                offsets['header'] = (self.headerOffset,0)
            for id in sortedObjectsIds:
                indirectObject = indirectObjects[id]
                if indirectObject != None:
                    objectOffset = indirectObject.getOffset()
                    object = indirectObject.getObject()
                    if object != None and object.isCompressed():
                        compressedIn = object.getCompressedIn()
                        if compressedIn in objectStreamsOffsets:
                            objectOffset = objectStreamsOffsets[compressedIn] + objectOffset + 20    
                    size = indirectObject.getSize()
                    if 'objects' in offsets:
                        offsets['objects'].append((id,objectOffset,size))
                    else:
                        offsets['objects'] = [(id,objectOffset,size)]
            if xref != None:
                xrefOffset = xref.getOffset()
                xrefSize = xref.getSize()
                offsets['xref'] = (xrefOffset, xrefSize)
            else:
                offsets['xref'] = None
            if trailer != None:
                trailerOffset = trailer.getOffset()
                trailerSize = trailer.getSize()
                eofOffset = trailer.getEOFOffset()
                offsets['trailer'] = (trailerOffset,trailerSize)
                offsets['eof'] = (eofOffset,0)
            else:
                offsets['trailer'] = None
                offsets['eof'] = None
            offsets['compressed'] = compressedObjects
            offsetsArray.append(offsets)
        return offsetsArray

    def getOwnerPass(self):
        return self.ownerPass
    
    def getPath(self):
        return self.path
    
    def getReferencesIn (self, id, version = None) :
        ''' 
            Get the references in an object
        '''
        if version == None:
            for i in range(self.updates,-1,-1):
                indirectObjectsDict = self.body[i].getObjects()
                if id in indirectObjectsDict:
                    indirectObject = indirectObjectsDict[id]
                    if indirectObject == None:
                        return None
                    else:
                        return indirectObject.getReferences()
            else:
                return None
        else:
            if version > self.updates or version < 0:
                return None
            indirectObjectsDict = self.body[version].getObjects()
            if id in indirectObjectsDict:
                indirectObject = indirectObjectsDict[id]
                if indirectObject == None:
                    return None
                else:
                    return indirectObject.getReferences()
            else:
                return None
    
    def getReferencesTo (self, id, version = None) :
        ''' 
            Get the references to the specified object in the document
        '''
        matchedObjects = []
        if version == None:
            for i in range(self.updates + 1):
                indirectObjectsDict = self.body[i].getObjects()
                for indirectObject in list(indirectObjectsDict.values()):
                    if indirectObject != None:
                        object = indirectObject.getObject()
                        if object != None:
                            value = object.getValue()
                            if re.findall(r'\D' + str(id) + r'\s{1,3}\d{1,3}\s{1,3}R', value) != []:
                                matchedObjects.append(indirectObject.id)
        else:
            if version > self.updates or version < 0:
                return None
            indirectObjectsDict = self.body[version].getObjects()
            for indirectObject in list(indirectObjectsDict.values()):
                if indirectObject != None:
                    object = indirectObject.getObject()
                    if object != None:
                        value = object.getValue()
                        if re.findall(r'\D' + str(id) + r'\s{1,3}\d{1,3}\s{1,3}R', value) != []:
                            matchedObjects.append(indirectObject.id)
        return matchedObjects

    def getSHA1(self):
        return self.sha1
    
    def getSHA256(self):
        return self.sha256
    
    def getSize(self):
        return self.size
        
    def getStats (self):
        stats = {}
        stats['File'] = self.fileName
        stats['MD5'] = self.md5
        stats['SHA1'] = self.sha1
        stats['SHA256'] = self.sha256
        stats['Size'] = str(self.size)
        stats['Detection'] = self.detectionRate
        stats['Detection report'] = self.detectionReport
        stats['Version'] = self.version
        stats['Binary'] = str(self.binary)
        stats['Linearized'] = str(self.linearized)
        stats['Encrypted'] = str(self.encrypted)
        stats['Encryption Algorithms'] = self.encryptionAlgorithms
        stats['Updates'] = str(self.updates)
        stats['Objects'] = str(self.numObjects)
        stats['Streams'] = str(self.numStreams)
        stats['URIs'] = str(self.numURIs)
        stats['Comments'] = str(len(self.comments))
        stats['Errors'] = self.errors
        stats['Versions'] = []
        for version in range(self.updates+1):
            statsVersion = {}
            catalogId = None
            infoId = None
            trailer, streamTrailer = self.trailer[version]
            if trailer != None:
                catalogId = trailer.getCatalogId()
                infoId = trailer.getInfoId()
            if catalogId == None and streamTrailer != None:
                catalogId = streamTrailer.getCatalogId()
            if infoId == None and streamTrailer != None:
                infoId = streamTrailer.getInfoId()
            if catalogId != None:
                statsVersion['Catalog'] = str(catalogId)
            else:
                statsVersion['Catalog'] = None
            if infoId != None:
                statsVersion['Info'] = str(infoId)
            else:
                statsVersion['Info'] = None
            objectsById = sorted(self.body[version].getObjectsIds(), key=lambda x: int(x))
            statsVersion['Objects'] = [str(self.body[version].getNumObjects()),objectsById]
            if self.body[version].containsCompressedObjects():
                compressedObjects = self.body[version].getCompressedObjects()
                statsVersion['Compressed Objects'] = [str(len(compressedObjects)),compressedObjects]
            else:
                statsVersion['Compressed Objects'] = None
            numFaultyObjects = self.body[version].getNumFaultyObjects()
            if numFaultyObjects > 0:
                statsVersion['Errors'] = [str(numFaultyObjects),self.body[version].getFaultyObjects()]
            else:
                statsVersion['Errors'] = None
            numStreams = self.body[version].getNumStreams()
            statsVersion['Streams'] = [str(numStreams),self.body[version].getStreams()]
            if self.body[version].containsXrefStreams():
                xrefStreams = self.body[version].getXrefStreams()
                statsVersion['Xref Streams'] = [str(len(xrefStreams)),xrefStreams]
            else:
                statsVersion['Xref Streams'] = None
            if self.body[version].containsObjectStreams():
                objectStreams = self.body[version].getObjectStreams()
                statsVersion['Object Streams'] = [str(len(objectStreams)),objectStreams]
            else:
                statsVersion['Object Streams'] = None
            if numStreams > 0:
                statsVersion['Encoded'] = [str(self.body[version].getNumEncodedStreams()),self.body[version].getEncodedStreams()]
                numDecodingErrors = self.body[version].getNumDecodingErrors()
                if numDecodingErrors > 0:
                    statsVersion['Decoding Errors'] = [str(numDecodingErrors),self.body[version].getFaultyStreams()]
                else:
                    statsVersion['Decoding Errors'] = None
            else:
                statsVersion['Encoded'] = None
            containingURIs = self.body[version].getContainingURIs()
            if len(containingURIs) > 0:
                statsVersion['URIs'] = [str(len(containingURIs)), containingURIs]
            else:
                statsVersion['URIs'] = None
            containingJS = self.body[version].getContainingJS()
            if len(containingJS) > 0:
                statsVersion['Objects with JS code'] = [str(len(containingJS)),containingJS]
            else:
                statsVersion['Objects with JS code'] = None
            actions = self.body[version].getSuspiciousActions()
            events = self.body[version].getSuspiciousEvents()
            vulns = self.body[version].getVulns()
            elements = self.body[version].getSuspiciousElements()
            urls = self.body[version].getURLs()
            if len(events) > 0:
                statsVersion['Events'] = events
            else:
                statsVersion['Events'] = None
            if len(actions) > 0:
                statsVersion['Actions'] = actions
            else:
                statsVersion['Actions'] = None
            if len(vulns) > 0:
                statsVersion['Vulns'] = vulns
            else:
                statsVersion['Vulns'] = None
            if len(elements) > 0:
                statsVersion['Elements'] = elements
            else:
                statsVersion['Elements'] = None
            if len(urls) > 0:
                statsVersion['URLs'] = urls
            else:
                statsVersion['URLs'] = None
            stats['Versions'].append(statsVersion)
        return stats

    def getSuspiciousComponents (self) :
        pass
            
    def getTrailer (self, version = None) :
        if version == None:
            for i in range(self.updates,-1,-1):
                trailerArray = self.trailer[i]
                if trailerArray == None or trailerArray == []:
                    continue
                else:
                    return (i,trailerArray)
            else:
                #self.addError('Trailer not found in file')
                return None
        else:
            if version > self.updates or version < 0:
                #self.addError('Bad version getting trailer')
                return None
            trailerArray = self.trailer[version]
            if trailerArray == None or trailerArray == []:
                return None
            else:
                return (version,trailerArray)

    def getTree (self, version = None) :
        '''
            Returns the logical structure (tree) of the document
        '''
        tree = []
        
        if version == None:
            versions = list(range(self.updates+1))
        else:
            versions = [version]
            
        for version in versions:
            objectsIn = {}
            trailer = None
            streamTrailer = None
            catalogId = None
            infoId = None
            ids = self.body[version].getObjectsIds()
            ret = self.getTrailer(version)
            if ret != None:
                trailer, streamTrailer = ret[1]
            # Getting info and catalog id
            if trailer != None:
                catalogId = trailer.getCatalogId()
                infoId = trailer.getInfoId()
            if catalogId == None and streamTrailer != None:
                catalogId = streamTrailer.getCatalogId()
            if infoId == None and streamTrailer != None: 
                infoId = streamTrailer.getInfoId()
            for id in ids:
                referencesIds = []
                object = self.getObject(id, version)
                if object != None:
                    type = object.getType()    
                    if type == 'dictionary' or type == 'stream':
                        elements = object.getElements()
                        if infoId == id:
                            type = '/Info'
                        else:
                            dictType = object.getDictType()
                            if dictType != '':
                                type = dictType
                            else:
                                if type == 'dictionary' and len(elements) == 1:
                                    type = list(elements.keys())[0]
                    references = self.getReferencesIn(id, version)
                    for i in range(len(references)):
                        referencesIds.append(int(references[i].split()[0]))
                    if references == None:
                        objectsIn[id] = (type, [])
                    else:
                        objectsIn[id] = (type, referencesIds)
            tree.append([catalogId, objectsIn])
        return tree

    def getUpdates(self):
        return self.updates    

    def getURLs (self, version = None) :
        urls = []
        if version == None:
            for version in range(self.updates+1):
                urls += self.body[version].getURLs()
        else:
            if version <= self.updates and not version < 0:
                urls = self.body[version].getURLs()
        return urls 

    def getURIs(self, version=None, perObject=False):
        uris = []
        if version is None:
            for version in range(self.updates+1):
                if perObject:
                    uris.append(self.body[version].getURIsPerObject())
                else:
                    uris.append(self.body[version].getURIs())
        else:
            if version <= self.updates and not version < 0:
                if perObject:
                    uris.append(self.body[version].getURIsPerObject())
                else:
                    uris.append(self.body[version].getURIs())
        return uris

    def getUserPass(self):
        return self.userPass
    
    def getVersion(self):
        return self.version

    def getXrefSection (self, version = None) :
        if version == None:
            for i in range(self.updates,-1,-1):
                xrefArray = self.crossRefTable[i]
                if xrefArray == None or xrefArray == []:
                    continue
                else:
                    return (i,xrefArray)
            else:
                #self.addError('Xref section not found in file')
                return None
        else:
            if version > self.updates or version < 0:
                return None
            xrefArray = self.crossRefTable[version]
            if xrefArray == None or xrefArray == []:
                return None
            else:
                return (version,xrefArray)
                
    def headerToFile(self, malformedOptions, headerFile):
        headerGarbage = ''
        if MAL_ALL in malformedOptions or MAL_HEAD in malformedOptions:
            if headerFile == None:
                if self.garbageHeader == '':
                    headerGarbage = 'MZ'+'_'*100
                else:
                    headerGarbage = self.garbageHeader
            else:
                headerGarbage = open(headerFile,'rb').read()
            headerGarbage += newLine
        if MAL_ALL in malformedOptions or MAL_BAD_HEAD in malformedOptions:
            output = headerGarbage + '%PDF-1.\0' + newLine
        else:
            output = headerGarbage + '%PDF-' + self.version + newLine
        if self.binary or headerGarbage != '':
            self.binary = True
            self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
            output += '%' + self.binaryChars + newLine
        return output
    
    def isEncrypted(self):
        return self.encrypted

    def makePDF(self, pdfType, content):
        offset = 0
        numObjects = 3
        self.version = '1.7'
        xrefEntries = []
        staticIndirectObjectSize = 13+3*len(newLine)
        self.setHeaderOffset(offset)
        if pdfType == 'open_action_js':
            self.binary = True
            self.binaryChars = '\xC0\xFF\xEE\xFA\xBA\xDA'
            offset = 16
        else:
            offset = 10
            
        # Body
        body = PDFBody()
        xrefEntries.append(PDFCrossRefEntry(0,65535,'f'))
        # Catalog (1)
        catalogElements = {'/Type':PDFName('Catalog'),'/Pages':PDFReference('2')}
        if pdfType == 'open_action_js':
            catalogElements['/OpenAction'] = PDFReference('4')
        catalogDictionary = PDFDictionary(elements=catalogElements)
        catalogSize = staticIndirectObjectSize + len(catalogDictionary.getRawValue())
        body.setObject(object = catalogDictionary, offset = offset)
        xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
        offset += catalogSize
        # Pages root node (2)
        pagesDictionary = PDFDictionary(elements={'/Type':PDFName('Pages'),'/Kids':PDFArray(elements=[PDFReference('3')]),'/Count':PDFNum('1')})
        pagesSize = len(pagesDictionary.getRawValue())+staticIndirectObjectSize
        body.setObject(object = pagesDictionary, offset = offset)
        xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
        offset += pagesSize
        # Page node (3)
        mediaBoxArray = PDFArray(elements=[PDFNum('0'),PDFNum('0'),PDFNum('600'),PDFNum('800')])
        pageDictionary = PDFDictionary(elements={'/Type':PDFName('Page'),'/Parent':PDFReference('2'),'/MediaBox':mediaBoxArray,'/Resources':PDFDictionary()})
        pageSize = len(pageDictionary.getRawValue())+staticIndirectObjectSize
        body.setObject(object = pageDictionary, offset = offset)
        xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
        offset += pageSize
        if pdfType == 'open_action_js':
            # Action object (4)
            actionDictionary = PDFDictionary(elements={'/Type':PDFName('Action'),'/S':PDFName('JavaScript'),'/JS':PDFReference('5')})
            actionSize = len(actionDictionary.getRawValue())+staticIndirectObjectSize
            body.setObject(object = actionDictionary, offset = offset)
            xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
            offset += actionSize
            # JS stream (5)
            try:
                jsStream = PDFStream(rawStream = content, elements = {'/Length':PDFNum(str(len(content)))})
            except Exception as e:
                errorMessage = 'Error creating PDFStream'
                if e.message != '':
                    errorMessage += ': '+e.message
                return (-1, errorMessage)
            ret = jsStream.setElement('/Filter',PDFName('FlateDecode'))
            if ret[0] == -1:
                self.addError(ret[1])
                return ret
            jsSize = len(jsStream.getRawValue())+staticIndirectObjectSize
            ret = body.setObject(object = jsStream, offset = offset)
            if ret[0] == -1:
                self.addError(ret[1])
                return ret
            xrefEntries.append(PDFCrossRefEntry(offset,0,'n'))
            offset += jsSize
            numObjects = 5
        body.setNextOffset(offset)
        self.addBody(body)
        self.addNumObjects(body.getNumObjects())
        self.addNumStreams(body.getNumStreams())
        self.addNumEncodedStreams(body.getNumEncodedStreams())
        self.addNumDecodingErrors(body.getNumDecodingErrors())
        
        # xref table
        subsection = PDFCrossRefSubSection(0,numObjects+1,xrefEntries)
        xrefSection = PDFCrossRefSection()
        xrefSection.addSubsection(subsection)
        xrefSection.setOffset(offset)
        xrefOffset = offset
        xrefSectionSize = len(xrefEntries)*20+10
        xrefSection.setSize(xrefSectionSize)
        offset += xrefSectionSize
        self.addCrossRefTableSection([xrefSection,None])
        
        # Trailer
        trailerDictionary = PDFDictionary(elements={'/Size':PDFNum(str(numObjects+1)),'/Root':PDFReference('1')})
        trailerSize = len(trailerDictionary.getRawValue())+25
        trailer = PDFTrailer(trailerDictionary,str(xrefOffset))
        trailer.setOffset(offset)
        trailer.setSize(trailerSize)
        trailer.setEOFOffset(offset+trailerSize)
        self.addTrailer([trailer,None])
        self.setSize(offset+trailerSize+5)
        self.updateStats()
        return (0,'')

    def replace(self, string1, string2):
        errorMessage = ''
        stringFound = False
        for i in range(self.updates + 1):
            objects = self.getObjectsByString(string1,i)
            for id in objects:
                object = self.getObject(id, i)
                if object != None:
                    ret = object.replace(string1, string2)
                    if ret[0] == -1 and not stringFound:
                        errorMessage = ret[1]
                    else:
                        stringFound = True
                        ret = self.setObject(id, object, i)
                        if ret[0] == -1:
                            errorMessage = ret[1]
        if not stringFound:
            return (-1,'String not found')
        if errorMessage != '':
            return (-1, errorMessage)
        else:
            return (0,'')

    def removeError(self, errorMessage = '', errorType = None):
        '''
            Removes the error message from the errors array. If an errorType is given, then all the error messages belonging to this type are removed.
        
            @param errorMessage: The error message to be removed (string)
            @param errorType: All the error messages of this type will be removed (string) 
        '''
        if errorMessage in self.errors:
            self.errors.remove(errorMessage)
        if errorType != None:
            lenErrorType = len(errorType)
            for error in self.errors:
                if error[:lenErrorType] == errorType:
                    self.errors.remove(error)
                
    def save(self, filename, version = None, malformedOptions = [], headerFile = None):
        maxId = 0
        offset = 0
        lastXrefSectionOffset = 0
        prevXrefSectionOffset = 0
        prevXrefStreamOffset = 0
        indirectObjects = {}
        xrefStreamObjectId = None
        xrefStreamObject = None
        try:
            if version == None:
                version = self.updates
            outputFileContent = self.headerToFile(malformedOptions,headerFile)
            offset = len(outputFileContent)
            for v in range(version+1):
                xrefStreamObjectId = None
                xrefStreamObject = None
                sortedObjectsIds = self.body[v].getObjectsIds()
                indirectObjects = self.body[v].getObjects()
                section, streamSection = self.crossRefTable[v]
                trailer, streamTrailer = self.trailer[v]
                if section != None:
                    numSubSectionsInXref = section.getSubsectionsNumber()
                else:
                    numSubSectionsInXref = 0
                if streamSection != None:
                    numSubSectionsInXrefStream = streamSection.getSubsectionsNumber()
                else:
                    numSubSectionsInXrefStream = 0
                if streamSection != None:
                    xrefStreamObjectId = streamSection.getXrefStreamObject()
                    if xrefStreamObjectId in indirectObjects:
                        xrefStreamObject = indirectObjects[xrefStreamObjectId]
                        sortedObjectsIds.remove(xrefStreamObjectId)
                for id in sortedObjectsIds:
                    if id > maxId:
                        maxId = id
                    indirectObject = indirectObjects[id]
                    if indirectObject != None:
                        object = indirectObject.getObject()
                        if object != None:
                            objectType = object.getType()
                            if not object.isCompressed():
                                indirectObject.setOffset(offset)
                                if numSubSectionsInXref != 0:
                                    ret = section.updateOffset(id, offset)
                                    if ret[0] == -1:
                                        ret = section.addEntry(id,PDFCrossRefEntry(offset,0,'n'))
                                        if ret[0] == -1:
                                            self.addError(ret[1])
                                if numSubSectionsInXrefStream != 0:
                                    ret = streamSection.updateOffset(id, offset)
                                    if ret[0] == -1:
                                        ret = streamSection.addEntry(id,PDFCrossRefEntry(offset,0,'n'))
                                        if ret[0] == -1:
                                            self.addError(ret[1])
                                objectFileOutput = indirectObject.toFile()
                                if objectType == 'stream' and MAL_ESTREAM in malformedOptions:
                                    objectFileOutput = objectFileOutput.replace(newLine+'endstream','')
                                elif MAL_ALL in malformedOptions or MAL_EOBJ in malformedOptions:
                                    objectFileOutput = objectFileOutput.replace(newLine+'endobj','')
                                outputFileContent += objectFileOutput
                                offset = len(outputFileContent)
                                indirectObject.setSize(offset-indirectObject.getOffset())
                                indirectObjects[id] = indirectObject
                    
                if xrefStreamObject != None:
                    if numSubSectionsInXref != 0:
                        ret = section.updateOffset(xrefStreamObjectId, offset)
                        if ret[0] == -1:
                            self.addError(ret[1])
                    ret = streamSection.updateOffset(xrefStreamObjectId, offset)
                    if ret[0] == -1:
                        self.addError(ret[1])
                    xrefStreamObject.setOffset(offset)
                    if xrefStreamObjectId > maxId:
                        maxId = xrefStreamObjectId
                    streamSection.setSize(maxId+1)
                    if streamTrailer != None:
                        streamTrailer.setNumObjects(maxId+1)
                        if prevXrefStreamOffset != 0:
                            streamTrailer.setPrevCrossRefSection(prevXrefStreamOffset)
                        self.trailer[v][1] = streamTrailer
                    self.crossRefTable[v][1] = streamSection
                    ret = self.createXrefStream(v, xrefStreamObjectId)
                    if ret[0] == -1:
                        return (-1,ret[1])
                    xrefStreamObjectId,newXrefStream = ret[1]
                    xrefStreamObject.setObject(newXrefStream)
                    objectFileOutput = xrefStreamObject.toFile()
                    if MAL_ALL in malformedOptions or MAL_ESTREAM in malformedOptions:
                        objectFileOutput = objectFileOutput.replace(newLine+'endstream','')
                    outputFileContent += objectFileOutput
                    prevXrefStreamOffset = offset
                    lastXrefSectionOffset = offset
                    offset = len(outputFileContent)
                    xrefStreamObject.setSize(offset-xrefStreamObject.getOffset())
                    indirectObjects[xrefStreamObjectId] = xrefStreamObject
                self.body[v].setNextOffset(offset)    
                                        
                if section != None and MAL_ALL not in malformedOptions and MAL_XREF not in malformedOptions:
                    section.setOffset(offset)
                    lastXrefSectionOffset = offset
                    outputFileContent += section.toFile()
                    offset = len(outputFileContent)
                    section.setSize(offset-section.getOffset())
                    self.crossRefTable[v][0] = section
                    
                if trailer != None:
                    trailer.setLastCrossRefSection(lastXrefSectionOffset)
                    trailer.setOffset(offset)
                    if trailer.getCatalogId() != None and trailer.getSize() != 0:
                        trailer.setNumObjects(maxId+1)
                        if prevXrefSectionOffset != 0:
                            trailer.setPrevCrossRefSection(prevXrefSectionOffset)
                    outputFileContent += trailer.toFile()
                    offset = len(outputFileContent)
                    trailer.setSize(offset-trailer.getOffset())
                    self.trailer[v][0] = trailer
                prevXrefSectionOffset = lastXrefSectionOffset
                self.body[v].setObjects(indirectObjects)
                offset = len(outputFileContent)
            open(filename,'wb').write(outputFileContent)
            self.setMD5(hashlib.md5(outputFileContent).hexdigest())
            self.setSize(len(outputFileContent))
            self.path = os.path.realpath(filename)
            self.fileName = filename
        except:
            return (-1,'Unspecified error')
        return (0,'')

    def setDetectionRate(self, newRate):
        self.detectionRate = newRate

    def setDetectionReport(self, detectionReportLink):
        self.detectionReport = detectionReportLink
        
    def setEncryptDict(self, dict):
        self.encryptDict = dict

    def setEncrypted(self, status):
        self.encrypted = status    

    def setEncryptionAlgorithms(self, encryptionAlgorithms):
        self.encryptionAlgorithms = encryptionAlgorithms

    def setEncryptionKey(self, key):
        self.encryptionKey = key    

    def setEncryptionKeyLength(self, length):
        self.encryptionKeyLength = length
                            
    def setEndLine(self, eol):
        self.endLine = eol    

    def setFileId(self, fid):
        self.fileId = fid
        
    def setFileName(self, name):
        self.fileName = name

    def setGarbageHeader(self, garbage):
        self.garbageHeader = garbage

    def setHeaderOffset(self, offset):
        self.headerOffset = offset

    def setLinearized(self, status):
        self.linearized = status

    def setMaxObjectId(self, id):
        if int(id) > self.maxObjectId:
            self.maxObjectId = int(id)
        
    def setMD5(self, md5):
        self.md5 = md5
                
    def setObject (self, id, object, version = None, mod = False):
        errorMessage = ''
        if object == None:
            return (-1,'Object is None')
        if version == None:
            for i in range(self.updates,-1,-1):
                ret = self.body[i].setObject(id, object, modification = mod)
                if ret[0] == -1:
                    errorMessage = ret[1]
                else:
                    objectType = object.getType()
                    if objectType == 'dictionary' and object.hasElement('/Linearized'):
                        self.setLinearized(True)
                    return ret
            else:
                return (-1, errorMessage)
        else:
            if version > self.updates or version < 0:
                return (-1,'Bad file version')
            ret = self.body[version].setObject(id, object, modification = mod)
            if ret[0] == -1:
                self.addError(ret[1])
                return (-1,ret[1])
            else:
                objectType = object.getType()
                if objectType == 'dictionary' and object.hasElement('/Linearized'):
                    self.setLinearized(True)
                return ret

    def setOwnerPass(self, password):
        self.ownerPass = password    
        
    def setPath(self, path):
        self.path = path

    def setSHA1(self, sha1):
        self.sha1 = sha1

    def setSHA256(self, sha256):
        self.sha256 = sha256

    def setSize(self, size):
        self.size = size
                
    def setTrailer(self, trailerArray, version = None):
        errorMessage = ''
        if version == None:
            for i in range(self.updates,-1,-1):
                if len(self.trailer) > i:
                    self.trailer[i] = trailerArray
                else:
                    errorMessage = 'Trailer not found'
                    self.addError(errorMessage)
        else:
            if version > self.updates or version < 0:
                return (-1,'Bad file version')
            self.trailer[version] = trailerArray
        if errorMessage != '':
            return (-1, errorMessage)
        return (0,'')

    def setUpdates(self, num):
        self.updates = num    

    def setUserPass(self, password):
        self.userPass = password

    def setVersion(self, version):
        self.version = version
                
    def updateStats(self, recursiveUpdate = False):
        self.numObjects = 0
        self.numStreams = 0
        self.numEncodedStreams = 0
        self.numDecodingErrors = 0
        self.encrypted = False
        
        for v in range(self.updates+1):
            if recursiveUpdate:
                #TODO
                self.updateBody(v)
                self.updateCrossRefTable(v)
                self.updateTrailer(v)
            
            #body.updateObjects()
            self.addNumObjects(self.body[v].getNumObjects())
            self.addNumStreams(self.body[v].getNumStreams())
            self.addNumEncodedStreams(self.body[v].getNumEncodedStreams())
            self.addNumDecodingErrors(self.body[v].getNumDecodingErrors())
            self.addNumURIs(self.body[v].getNumURIs())
            trailer, streamTrailer = self.trailer[v]
            if trailer != None:
                if trailer.getDictEntry('/Encrypt') != None:
                    self.setEncrypted(True)
            if streamTrailer != None:
                if streamTrailer.getDictEntry('/Encrypt') != None:
                    self.setEncrypted(True)
        return (0,'')

    def updateBody (self, version) :
        #TODO
        pass
    
    def updateCrossRefTable (self, version) :
        #TODO
        pass
    
    def updateTrailer (self, version) :
        #TODO
        pass
