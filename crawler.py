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
import pickle
import signal

import deobfusc
 
#Definition de constantes utiles

#Couleur
HEADER = '\033[95m'
ENDC = '\033[0m'
OKGREEN = '\033[92m'
OKBLUE = '\033[94m'
BOLD = '\033[1m'
FAIL = '\033[91m'

websites = {'xssed' : [], 'dmoz' : []}

features = []

htmlFeat = ['<script>', '<iframe>', '<meta>', '<div>', 'href', 'http-equiv', 'lowsrc', 'onclick', 'onmouseover', 'onload', 'window', 'location', 'document', 'cookie', 'referrer', 'innerhtml', 'write()', 'getelementbytagname()', 'alert()', 'eval()']

def timeoutHandler(signum, frame):
    raise Exception('Timeout')
     
def xssed_crawl(nb_website, page = 1):

    print(BOLD + OKGREEN + "Crawling des pages inféctés depuis www.xssed.com" + ENDC + '\n')

    websites_remaining = nb_website

    while(websites_remaining):

        try:
            parentHtml = urllib.request.urlopen('http://www.xssed.com/archive/page=' + str(page) + '/').read().decode('latin-1')
        except Exception as e:
            print('\n' + "Erreur : " + FAIL + str(e.type) + " = " + str(e) + ENDC + '\n')
            continue

        for website in [m.start() + len("/mirror/") for m in re.finditer("/mirror/", parentHtml)]:
            signal.alarm(60*10) #Si l'iteration met plus de 10 minutes je la saute simplement 

            mirrorInd = parentHtml[website:parentHtml.find("/", website)]
            
            try:
                mirrorHtml = urllib.request.urlopen('http://www.xssed.com/mirror/' + str(mirrorInd) + '/').read().decode('latin-1')
            except Exception as e:
                print('\n' + "Erreur : " + FAIL + str(type(e)) + " = " + str(e) + ENDC + '\n')
                continue

            vulnUrl = mirrorHtml[mirrorHtml.find("http://vuln.xssed.net/"):mirrorHtml.find('"', mirrorHtml.find("http://vuln.xssed.net/"))]
            trueUrl = mirrorHtml[mirrorHtml.find("URL: ") + 5:mirrorHtml.find('</th', mirrorHtml.find("URL: "))] 

            items = re.findall("&gt;", trueUrl)
            for item in items:
                trueUrl = trueUrl.replace(item, ">")

            items = re.findall("&lt;", trueUrl)
            for item in items:
                trueUrl = trueUrl.replace(item, "<")


            try:
                vulnHtml = urllib.request.urlopen(vulnUrl).read().decode('latin-1')
            except Exception as e:
                print('\n' + "Erreur : " + FAIL + str(type(e)) + " = " + str(e) + ENDC + '\n')
                continue
            
            websites['xssed'].append( ( trueUrl, vulnHtml ) )
            sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website - websites_remaining + 1) + " / " + str(nb_website) + ENDC) 
            sys.stdout.flush()

            websites_remaining -= 1
            if(not websites_remaining):
                break;

            signal.alarm(0)
                
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
                urlW = line[line.find('r:resource="') + len('r:resource="'):line.find('>') - 1]
                htmlW = urllib.request.urllopen(urlW).read().decode('latin-1')
                websites['dmoz'].append((urlW, htmlW))
            except Exception as e:
                print('\n' + "Erreur : " + FAIL + str(type(e)) + " = " + str(e) + ENDC + '\n')
                continue

            website_remaining -= 1
            sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website - website_remaining) + " / " + str(nb_website) + ENDC)
            if(not website_remaining):
                break
    
    sys.stdout.write("\r" + OKBLUE + "Avancement : " + str(nb_website) + " / " + str(nb_website) + ENDC + ' '*10 + BOLD + OKGREEN + 'Termine !' + ENDC + '\n\n')

def getObfuscFeatures(url, code):
    """ Cette fonction calcule les features en relation avec l'obfuscation 
    1) Difference entre l'URL décodé en l'original
    2) Difference entre le code source décodé et l'original
    3) Taille de l'URL original """
    return (len(url) - len(deobfusc.decode(url))), (len(code) -len(deobfusc.decode(code))), len(url)

#Pour le moment je n'utilise pas de features en relation avec les mot clés suspects je verrai ce que ca donne
def getSuspFeatures(url, code):
    """ Cette fonction calcule les suspicious-based features 
    1) Nombre de domaines .
    2) Caracteres duppliqués
    3) Mot clés suspects """
    return (len(re.findall('([0-9A-Za-z_-]+\\.){2}[0-9A-Za-z_-]+')) + len(re.findall('([0-9]+\\.){3}[0-9]+'))), ('<<' in (url + code) or '>>' in (url + code) )
   
def gerTagsSchemes(code):
    """Cette fonction retourne les features en relation avec le HTML Tags """
    code = code.lower()

    tagsF = []
    
    for e in htmlFeat:
        if e in code:
            tagsF.append(1)
        else:
            tagsF.append(0)
    
    return tagsF

signal.signal(signal.SIGALRM, timeoutHandler)
#Test
xssed_crawl(3000, 601)

f = open('xss_dataset_7.pickle', 'wb')
pickle.dump(websites, f)
xssed_crawl(3000, 701)

f = open('xss_dataset_8.pickle', 'wb')
pickle.dump(websites, f)
xssed_crawl(3000, 801)

f = open('xss_dataset_9.pickle', 'wb')
pickle.dump(websites, f)
xssed_crawl(3000, 901)

f = open('xss_dataset_10.pickle', 'wb')
pickle.dump(websites, f)
