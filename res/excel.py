from xml.dom import minidom
import openpyxl
import re

class invictiXMLParser:
    def __init__(self):
        self.vulnerabilities={}

    def xmlParser(self, file):
        def value(node):
            try:return node[0].firstChild.nodeValue
            except: return ''

        dom = minidom.parse(file)
        vulnerabilities=dom.getElementsByTagName('vulnerability')
        for vulnerability in vulnerabilities:
            name=value(vulnerability.getElementsByTagName('type'))
            if not name in self.vulnerabilities:
                self.vulnerabilities[name]={'id':name,'name':value(vulnerability.getElementsByTagName('title')), 'urls':[], 'classifications':[], 'cvss_vector':'', 'cvss_score':''}
                self.vulnerabilities[name]['risk_factor']=value(vulnerability.getElementsByTagName('severity'))

                for cve in vulnerability.getElementsByTagName('references'):
                    cve = cve.firstChild.nodeValue if cve.firstChild else ''
                    if 'CVE' in cve: self.vulnerabilities[name]['classifications'].append(cve)
                cwes=value(vulnerability.getElementsByTagName('CWE')).strip().split(',')
                for cwe in cwes: 
                    if len(cwe.strip()):
                        self.vulnerabilities[name]['classifications'].append('CWE-'+cwe.strip())

                self.vulnerabilities[name]['description']=value(vulnerability.getElementsByTagName('description'))
                self.vulnerabilities[name]['impact']=value(vulnerability.getElementsByTagName('impact'))
                self.vulnerabilities[name]['remediation']=value(vulnerability.getElementsByTagName('remedy'))
                self.vulnerabilities[name]['reference_links']=[re.sub(r'.*(?:href=\'(.*?)\').*', r'\1' ,value(vulnerability.getElementsByTagName('remedyReferences')).strip())]
                
                cvss=vulnerability.getElementsByTagName('CVSS')
                if len(cvss): 
                    self.vulnerabilities[name]['cvss_vector']=value(cvss[0].getElementsByTagName('vector'))
                    self.vulnerabilities[name]['cvss_score']=value(cvss[0].getElementsByTagName('value'))
                    self.vulnerabilities[name]['risk_factor']=value(cvss[0].getElementsByTagName('severity'))
                    
            url=value(vulnerability.getElementsByTagName('url'))
            if url not in self.vulnerabilities[name]['urls']:self.vulnerabilities[name]['urls'].append(url)

    def excel(self):
        def severities_sort(x):
            severities=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW','BESTPRACTICE', 'INFORMATIONAL', 'INFO']
            for sev in severities:
                if x[1]['risk_factor'].upper() in sev: 
                    return severities.index(sev)
            return 1

        vuls=sorted(self.vulnerabilities.items(), key=lambda x: float(x[1]['cvss_score']) if not x[1]['cvss_score']=='' else 0.0, reverse=True)

        vuls=sorted(vuls, key=severities_sort)

        base=openpyxl.load_workbook('res/base.xlsx')
        wb=base.active
        i=0
        for vul in vuls:
            vuldata=self.vulnerabilities[vul[0]]
            row=str(i+2)
            wb['A'+row]=row
            wb['B'+row]=re.sub(r'<.*?>','',vuldata['name'])
            wb['C'+row]=', '.join(vuldata['urls'])
            wb['D'+row]=vuldata['risk_factor']
            wb['E'+row]=vuldata['cvss_score']
            wb['F'+row]=vuldata['cvss_vector']
            wb['G'+row]=', '.join(vuldata['classifications'])
            wb['H'+row]=''
            wb['I'+row]=re.sub(r'<.*?>','',vuldata['description'])
            wb['J'+row]=re.sub(r'<.*?>','',vuldata['impact'])
            wb['K'+row]=re.sub(r'<.*?>','',vuldata['remediation'])
            wb['L'+row]=', '.join(vuldata['reference_links'])
            i+=1
        base.save('export.xlsx')
