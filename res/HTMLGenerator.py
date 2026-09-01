from glob import glob
import shutil
import openpyxl
import glob
import re
import json
import os


class HTMLGenerator:
    def __init__(self):
        self.vulnerabilities={}

    def parseExcel(self, file):
        data=openpyxl.load_workbook(file).active
        for row in data.iter_rows(min_row=2, values_only=True):
            if row[1]==None:continue
            name=row[1].strip()
            if not name in self.vulnerabilities:
                self.vulnerabilities[name]={
                    'id':re.sub(r'[^\w]', '_', name),
                    'name':name, 'urls':list(map(lambda x: x.strip(), row[2].split(','))) if row[2] is not None else [], 
                    'risk_factor':row[3], 'cvss_score':row[4] if row[4] is not None else '', 'cvss_vector':row[5] if row[5] else '', 'cvss_classification':list(map(lambda x: x.strip(), row[6].split(','))) if row[6] else [], 'owasp': row[7].strip() if row[7] else '', 'description':row[8].strip() if row[8] else '', 'impact':row[9].strip() if row[9] else '', 'remedy':row[10].strip() if row[10] else '', 'reference_links':row[11].split(',') if len(row)>11 and row[11] is not None else []}

    def createHTML(self):
        def severities_sort(x):
            severities=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW','BESTPRACTICE', 'INFORMATIONAL', 'INFO']
            for sev in severities:
                if x[1]['risk_factor'].upper() in sev: 
                    return severities.index(sev)
            return 1
        
        vuls=sorted(self.vulnerabilities.items(), key=lambda x: float(x[1]['cvss_score']) if not x[1]['cvss_score']=='' else 0.0, reverse=True)
        vuls=sorted(vuls, key=severities_sort)
        vuls=list(map(lambda x: x[1], vuls))

        html=open('res/base.html', 'r').read()
        with open('export.html', 'w') as f: f.write(html.replace('{data}',json.dumps(vuls)))
        os.startfile('export.html')
        try:
            shutil.copy('res/base.docm', 'export.docm')
            os.startfile('export.docm')
        except Exception as e: print(e)


# parser=HTMLGenerator()
# files=glob.glob(input('Enter filename or wildcards: '))
# for file in files:
#     if file.endswith('.xlsx'):
#         parser.parseExcel(file)
# parser.createHTML()