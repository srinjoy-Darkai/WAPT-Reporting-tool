import sys
from res.excel import invictiXMLParser
from res.HTMLGenerator import HTMLGenerator
import glob
import os

HELP='''Usage is simple

Usage:
 --excel xml_file_name_or_wildcard (feeds xml from Invicti/Netspraker and creates excel)
 --word excel_file_name (creates report from excel) 


HELP: 
 Step 1: 
    Get the xml from Netsparker/Invicti
    Open Netsparker/Invicti -> load the session if not loaded -> go the reports tab -> on the most right side -> from the lists group, choose "Vulnerabilities List - Detailed (XML)"

 Step 2: 
    Generate excel using this tool

 Step 3:
    Edit the excel, add/remove vulnerabilities according to your needs

 Step 4: Generate work report from the excel
    After running the command successfully, you would get a html file opened in your default web browser, copy all the content from there, paste on the word file, which has opened, and then do manual changes according to your needs
'''


if '--excel' in sys.argv:
    files=sys.argv[sys.argv.index('--excel')+1]
    if files:
        parser=invictiXMLParser()
        files=glob.glob(files)
        if not len(files): 
            print('no file found with that keyword')
            exit()
        for file in files:
            if file.endswith('.xml'):
                print('Parsing ', file)
                parser.xmlParser(file)

        parser.excel()
        os.startfile('export.xlsx')
    else:print(HELP) 

elif '--word' in sys.argv:
    files=sys.argv[sys.argv.index('--word')+1]
    if not len(files): 
        print('no file found with that keyword')
        exit()
    if files:
        parser=HTMLGenerator()
        files=glob.glob(files)
        for file in files:
            if file.endswith('.xlsx'):
                parser.parseExcel(file)
        parser.createHTML()
    else: print(HELP)
else:
    print(HELP)