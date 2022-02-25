#!/usr/bin/python3

from Rules import *
from XmlReader import *
from Parser import *
from R import *
import sys


'''
RULE N°28

+ Opt out of cleartext traffic
-> https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted

? Pseudo Code:
	1. Check if ‘cleartextTrafficPermitted’ is set to true or not set in <domain-config> tag

! Output
	-> NOTHING	: No security config file found or no ‘cleartextTrafficPermitted’ true found
	-> WARNING	: ‘cleartextTrafficPermitted’ true found
'''

class Rule28(Rules):
	def __init__(self, directory, database, verbose=True, verboseDeveloper=False, storeManager=None, flowdroid=False, platform="",validation=False, quiet=True):
		Rules.__init__(self, directory, database, verbose, verboseDeveloper, storeManager, flowdroid, platform, validation, quiet)

		self.AndroidErrMsg = "clear text(s) permitted in networking security file"
		self.AndroidOkMsg1 = "no clear text permitted in networking security file"
		self.AndroidOkMsg2 = "no networking security file found"
		self.AndroidOkMsg = self.AndroidOkMsg1
		self.AndroidText = "https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted"

		self.okMsg = "no clear text permitted in networking security file"
		self.errMsg = "Set cleartextTrafficPermitted to False"
		self.category = R.CAT_2
		
		self.findXml()
		self.show(28, "Opt out of cleartext traffic")


	# This function returns the arg-value pair splitted
	def get_arg_value_split(self, arg):
		split = arg.split("=")
		argName = split[0].strip()
		val = split[1].strip()
		value = val[1:len(val)-1]
		return argName, value


	# Function used to check if a specific argument is present in a list: if that's the case, return its position in the list
	# It also returns the corresponding value
	def get_arg_index_and_value(self, args, arg):
		for i in range(len(args)):
			if arg in args[i]:
				_, value = self.get_arg_value_split(args[i])
				return i, value 		# found at index i
		return -1, None 				# not found


	# Function that outputs the XmlReader obj corresponding to an xml file different from AndroidManifest (e.g. network_security_config.xml)
    # 'arg_value' should be the xml argument value
    # it works by replacing the AndroidManifest path with the 'arg_value' one
	def analyse_non_manifest_xml(self, manifest_path, arg_value):
		# case where we check our developed app
		if 'build/intermediates/merged_manifest' in manifest_path:
			xml_file_path = manifest_path.replace('build/intermediates/merged_manifest/debug/AndroidManifest.xml', 'src/main/res/') + arg_value.replace('@', '') + '.xml'
		# case where we check an app decompiled from apk
		else:
			xml_file_path = manifest_path.replace('AndroidManifest.xml', 'res/') + arg_value.replace('@', '') + '.xml'
		# self.maxFiles += 1 # this is used as a display thing... --> let the interpreter add it!
		return XmlReader(xml_file_path)


	def run(self):
		self.loading()

		xmlReader = XmlReader(self.manifest)

		if self.manifest != None:
			violations = []
			application = xmlReader.getArgsTag('application')             
			args = application[0]['args']                       
			index, value = self.get_arg_index_and_value(args, "android:networkSecurityConfig")  

			if index >= 0:
				networkFileReader = self.analyse_non_manifest_xml(self.manifest, value)       
				self.maxFiles += 1
				domain = networkFileReader.getArgsTag('domain-config')         
				for d in domain: 
					args = d['args']
					dIndex, dValue = self.get_arg_index_and_value(args, "cleartextTrafficPermitted")     
					if dIndex >= 0:
						if dValue == "true":
							violations.append(d)

				violations = networkFileReader.constructToken(violations)
				violations = Parser.setMsg(violations, R.WARNING, self.errMsg)

				self.updateWN(networkFileReader.getFile(), violations)
				networkFileReader.close()

			self.loading()

			xmlReader.close()

			self.store(28, self.AndroidOkMsg, self.AndroidErrMsg, self.AndroidText, self.category)
			self.display(XmlReader)


