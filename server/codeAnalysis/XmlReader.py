#!/usr/bin/python3

import tempfile
from Parser import *
from R import *


class XmlReader():
	ARGS 		= "args"
	INSTR 		= "instr"
	ID			= "id"
	FILEPATH 	= "filepath"


	def __init__(self, filename, toParse=True):
		self.manifest = filename
		self.tmp = tempfile.NamedTemporaryFile(mode='w+', delete=True)
		self.error = False
		if toParse:
			self.parse()


	def parse(self):
		try:
			if self.manifestExists():
				manifest = ""
				with open(self.manifest, 'r') as f:
					while True:
						line = f.readline()
						if line == '':
							break
						manifest += line
				manifest = self.clearCommentXml(manifest)
				manifest = ' '.join(manifest.split())
				manifest = manifest.replace(' ', '\n').replace('/>', '\n/>').replace('">', '"\n>')
				self.tmp.write(manifest)	# write data in temporary file
				self.tmp.seek(0)
		except:
			self.error = True


	def clearCommentXml(self, code):
		output = []
		code_list = code.split('\n')		# get a list of the code by splitting according newlines
		for line in code_list:						
			if '<!--' in line:				# if in a code line we have '<!--' or '-->' ...
				code_part_left = line.split('<!--')[0]		# ... then take only the left/right part of the code line
				if code_part_left != '':
					output.append(code_part_left)
			if '-->' in line:
				code_part_right = line.split('-->')[1]
				if code_part_right != '':
					output.append(code_part_right)
			else:
				output.append(line)
		return '\n'.join(output)				# return the string of the code after converting from list


	def manifestExists(self):
		if self.manifest == None:
			return False
		return True


	def resetCursor(self):
		if self.tmp != None:
			self.tmp.seek(0)


	def close(self):
		self.tmp.close()


	def getFile(self):
		return self.manifest


	def getArgValue(self, arg):
		val = arg.split("=")[1]
		val = val[1:len(val)-1]
		return val


	def getArgsTag(self, tag):
		res = []
		if self.error:
			return res
		Id = 0
		line = self.tmp.readline()
		while line != '':
			line = line.strip()
			if line.startswith('<'+tag):
				arg 	= []
				instr 	= line
				line 	= self.tmp.readline()
				while (not line.startswith('/>')) and (not line.startswith('>')):
					line = line.strip()
					instr += ' ' + line
					if line != '':
						arg.append(line)
					line = self.tmp.readline()		
				output = {}
				output[XmlReader.ID] 	= Id
				output[XmlReader.ARGS] 	= arg
				output[XmlReader.INSTR] = instr.strip()
				output[XmlReader.FILEPATH] = self.getFile()
				res.append(output)
				Id += 1
			line = self.tmp.readline()
		self.resetCursor()
		return res


	def getArgsCond(self, tag, cond):
		res = []
		tags = self.getArgsTag(tag)
		index = 0
		line = self.tmp.readline()
		while line != '':
			line = line.strip()
			if line.startswith('<'+tag):
				line = self.tmp.readline()
				while (not line.startswith('/>')) and (not line.startswith('>')):
					line = self.tmp.readline()
				if line.startswith('>'):
					condChecked = False
					while (not line.startswith('</'+tag)):
						line = self.tmp.readline()
						if line.startswith('<'+cond):
							condChecked = True
					if condChecked:
						res.append(tags[index])
				index += 1
			line = self.tmp.readline()
		self.resetCursor()
		return res


	def constructToken(self, xmlReaderData):
		res = []
		for e in xmlReaderData:
			token = {}
			token[R.ERRORTYPE] = None
			token[R.ERRORMSG]	= None
			token[R.INSTR] 	= e[XmlReader.INSTR]
			res.append(token)
		return res


	def getLine(self, instr, tok):
		lineNumber = 1
		isFound = False
		instr = ' '.join(instr.split())
		code = ""
		with open(self.manifest, 'r') as f:
			while True:
				line = f.readline()
				if line == '':
					break
				line = ' '.join(line.split())
				code += ' ' + line
				code = self.clearCommentXml(code)
				code = ' '.join(code.split())
				if instr in code:
					isFound = True
					break
				lineNumber += 1
		self.resetCursor()
		if isFound == False:
			lineNumber = -1
		return lineNumber


