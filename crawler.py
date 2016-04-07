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
import sys
import os.path

#Definition de constantes utiles

#Couleur
HEADER = '\033[95m'
ENDC = '\033[0m'
OKGREEN = '\033[92m'
OKBLUE = '\033[94m'
BOLD = '\033[1m'
FAIL = '\033[91m'

websites = {'xssed' : [], 'dmoz' : []}

def xssed_crawl(nb_website):

    print(BOLD + OKGREEN + "Crawling des pages inféctés depuis www.xssed.com" + ENDC + '\n')

    websites_remaining = nb_website
    page = 1

    while(websites_remaining):

        try:
            parentHtml = urllib.request.urlopen('http://www.xssed.com/archive/page=' + str(page) + '/').read().decode('utf-8')
        except:
            continue

        for website in [m.start() + len("/mirror/") for m in re.finditer("/mirror/", parentHtml)]:
            mirrorInd = parentHtml[website:parentHtml.find("/", website)]
            
            try:
                mirrorHtml = urllib.request.urlopen('http://www.xssed.com/mirror/' + str(mirrorInd) + '/').read().decode('utf-8')
            except:
                continue

            vulnUrl = mirrorHtml[mirrorHtml.find("http://vuln.xssed.net/"):mirrorHtml.find('"', mirrorHtml.find("http://vuln.xssed.net/"))]
            
            try:
                vulnHtml = urllib.request.urlopen(vulnUrl).read().decode('latin-1')
            except:
                continue

            websites['xssed'].append(vulnHtml)
            sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website - websites_remaining + 1) + " / " + str(nb_website) + ENDC) 
            sys.stdout.flush()

            websites_remaining -= 1
            if(not websites_remaining):
                break;
                
        page += 1
    
    sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website) + " / " + str(nb_website) + ENDC + ' '*10 + BOLD + OKGREEN + 'Termine !' + ENDC + '\n\n')

def dmoz_crawl(nb_website):

    print(BOLD + OKGREEN + "Crawling des pages non inféctés depuis DMOZ" + ENDC + '\n')

    if(not os.path.isfile("content.rdf.u8")):
        print(BOLD + FAIL + "Le fichier content.rdf.u8 n'a pas été trouvé il sera téléchargé " + ENDC)
        print("Veuillez patientez ... ")

        urllib.request.urlretrieve("http://rdf.dmoz.org/rdf/content.rdf.u8.gz", "content.rdf.u8")
        print(BOLD + OKGREEN + "Telechargement terminé !")
    print("Debut du Crawling")

    website_remaining = nb_website

    #Normalement il y a un module XML qui est beaucup plus adapté
    #Mais le fichier est beaucoup trop volumineux (1.7 Go) et je n'ai que 3Go au moment du dévlopement x)
    for line in open("content.rdf.u8"):
        if('r:resource="' in line):

            try:
                websites['dmoz'].append(urllib.request.urlopen(line[line.find('r:resource="') + len('r:resource="'):line.find('>') - 1]).read().decode('latin-1'))
            except:
                continue

            website_remaining -= 1
            sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website - website_remaining) + " / " + str(nb_website) + ENDC)
            if(not website_remaining):
                break
    
    sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website) + " / " + str(nb_website) + ENDC + ' '*10 + BOLD + OKGREEN + 'Termine !' + ENDC + '\n\n')
    print(websites['dmoz'])        

#Test
dmoz_crawl(10)                      
        
