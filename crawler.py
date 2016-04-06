# -*- coding: utf-8 -*-
#!/usr/bin/python3

#####################################################################################
#
#  Auteur   :   Yassir Karroum [ukarroum17@gmail.com] [https://github.com/ukarroum/]
#
#  Description:
#
#  Crawler.py est un script que j'ai codé dans le but
#  de creer un Dataset assez large pour un autre projet xss-detector
#  dans le but d'entrainer les classificateurs . 
#  Ils construit le Dataset à partir de deux sites : www.xssed.com (qui contient
#  à ce jour 45.000 pages inféctés avec du XSS) et DMOZ qui contient 3M5 sites 
#  mais le script ne retiendra que 45.000 ce qui fera un jolie dataset d'une taille de 90.000 pages HTML
#  Ce nombre pourra bien évidement etre changé via le fichier de configuration 
###############################################################################

import urllib.request
import re

def xssd_crawl(nb_website):
    websites = []

    page = 1
    while(nb_website):
        parentHtml = urllib.request.urlopen('http://www.xssed.com/archive/page=' + str(page) + '/').read().decode('utf-8')
         
        for website in [m.start() + len("/mirror/") for m in re.finditer("/mirror/", parentHtml)]:
            mirrorInd = parentHtml[website:parentHtml.find("/", website)]
            mirrorHtml = urllib.request.urlopen('http://www.xssed.com/mirror/' + str(mirrorInd) + '/').read().decode('utf-8')

            vulnUrl = mirrorHtml[mirrorHtml.find("http://vuln.xssed.net/"):mirrorHtml.find('"', mirrorHtml.find("http://vuln.xssed.net/"))]
            vulnHtml = urllib.request.urlopen(vulnUrl).read().decode('latin-1')

            websites.append(vulnHtml)

            nb_website -= 1
            if(not nb_website):
                break;
                
        page += 1


#Test
xssd_crawl(10)                      
        
