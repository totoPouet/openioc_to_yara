#!/usr/bin/env python
# -*- coding: utf-8 -*-
#  2016, MS

# ANSSI file parsing
# URL : wide ascii nocase
# Hash, ip ,file name, ... : fullword
#
# csv_context_to_modifier  : link a context to a yara modifier

import os
import sys
import logging
import glob
import csv
import time
import argparse
import re
from lxml import etree

# logging config
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')

csvContextFile = "csv_context_to_modifier"
start_time = time.clock()
time.strftime("%H_%M_%S")

try:
    os.path.isfile(csvContextFile)
except ImportError, e:
    logging.error('Could not find csv_context_to_modifier file.')
    sys.exit(1)


def makeargpaser():
    try:

        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--input", required=True, help="Input : OpenIOC file for convertion")
        parser.add_argument("-o", "--output", help="Output : Yara rules file to generate",default=0)
        parser.add_argument("-m", "--mode", help="mode=1, stick to openioc file \n\tmode=2, 1 ioc for 1 rule",default='1')
        parser.add_argument("-d", "--debug", help="enable debug",default=0)
        args = parser.parse_args()
        return args

    except argparse.ArgumentError, exc:
        print exc.message, '\n', exc.argument


def debug_print(message):
    if debug == '1':
        print "[DEBUG] " + time.strftime("%H:%M:%S ") + str(message)

def set_modifier(ioc_context):
    with open(csvContextFile, 'rb') as csvfile:
        csv_map = csv.reader(csvfile, delimiter=',')
        for row in csv_map:
            if ioc_context == row[0]:
               return row[1]

def replace_char(string,chars):
    return re.sub('[' + re.escape(''.join(chars)) + ']','_',string)

def sanitize_regex(string):
    string.replace('/','\/')
    return string

def generate_output(filepath,message):
    f = open(filepath,"w+")
    f.writelines(message)
    f.close()

# Init options
args = makeargpaser()
openiocfile = args.input
debug = args.debug
mode = args.mode
yara_rules = ""
tree = etree.parse(openiocfile)
root = tree.getroot()
if args.output != '0':
    output_file = args.output
else:
    output_file = time.strftime("%H%M%S")+"_"+openiocfile.split(".")[0]+".yar"

debug_print("debug = "+str(debug)+ \
        "\n\t\tmode = "+str(mode)+ \
        "\n\t\tinput file = "+str(openiocfile)+ \
        "\n\t\toutput file = "+str(output_file))

##TODO : Check/Validate OpenIOC XML file
try:
    if root.tag != "ioc":
        raise Exception('Bad format OpenIOC file !')
except Exception as inst:
    print "[ERROR] : Bad format OpenIOC file !"
    raise
    exit(1)

#All in one rule
if  mode == '1':
    debug_print("Mode All in 1 !")
    ioc_strings = ""
    for ind  in  root.findall("./definition/Indicator"):
        debug_print(" "+str(ind.attrib))
        operator = ind.get('operator')
        indice = 0
        for item in ind.iter("IndicatorItem"):
            context = item.find('Context').get('search')
            ioc_type = item.find('Content').get('type')
            ioc_content = item.find('Content').text
            yara_mod = set_modifier(context)

            #if context == "PortItem/remoteIP" or context == "Network/URI" or context == "Network/DNS" :
            # Sanitize regex IOC
            if ioc_type == "regex":
                ioc_content = "/" + ioc_content.replace('/','\/') + "/"
            else:
                ioc_content = "\"" + ioc_content + "\""

            #debug_print("IOC : " + ioc_content)

            ioc_strings = ioc_strings + "\n\t\t$"+ioc_type+"_"+str(indice)+" = " + ioc_content + " " + yara_mod
            indice += 1

# 1 rule for 1 IOC
if mode == '2':
    debug_print("Mode 1 to 1!")
    for ind in  root.findall("./definition/Indicator"):
        #debug_print(ind.attrib)
        operator = ind.get('operator')
        indice = 0
        for item in ind.iter("IndicatorItem"):
            #debug_print(item.attrib)
            context = item.find('Context').get('search')
            ioc_type = item.find('Content').get('type')
            ioc_content = item.find('Content').text

            rule_name = replace_char(ioc_content,"%-\{\}:\.\\/")

            if context == "Snort/Snort":
                continue
            if ioc_type == "regex":
                ioc_content = "/" + ioc_content + "/"
                #ioc_content_esc = re.escape(ioc_content)
                #ioc_content_esc = "/"+ioc_content_esc+"/"
                debug_print("ioc_content " + ioc_content)
            else:
                ioc_content = "\"" + ioc_content + "\""

            yara_mod = set_modifier(context)

            '''
            debug_print("rule anssi_" + rule_name + "\n{\n\tstrings:\n\t\t"+"$"+ioc_type+"_"+ \
                    str(indice)+" = " + ioc_content + " " + yara_mod + \
                    "\n\n\tcondition:\n\t\t1 of them\n}\n")
            '''

            tmp_rule = "rule anssi_" + rule_name + "\n{\n\tstrings:\n\t\t"+"$"+ioc_type+"_"+ \
                    str(indice)+" = " + ioc_content + " " + yara_mod + \
                    "\n\n\tcondition:\n\t\t1 of them\n}\n"
            yara_rules = yara_rules + tmp_rule

            indice += 1

if mode == '1':
    rule_name = replace_char(openiocfile,"+%-\{\}:\.\\/")
    meta = "\n\tmeta:\n\t\tdescription = \"Yara rule generated from OpenIOC file : "+openiocfile+"\" \
            \n\t\tauthor = \""+ sys.argv[0]+" - MS \" \
            \n\t\tdate = \""+time.strftime("%d/%m/%Y %H:%M:%S")+"\"\n"

    yara_rules = "rule " + rule_name +"\n{" + meta + "\n\tstrings:\t\t"+ioc_strings \
            + "\n\n\tcondition:\n\t\t1 of them\n}\n"

#debug_print("Output : \n " + str(yara_rules))
generate_output(output_file,yara_rules)
