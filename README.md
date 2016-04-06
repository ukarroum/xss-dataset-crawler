# XSS Dataset Crawler 

## Introduction 
Un Crawler en Python qui permet de récuperer un large Dataset contenant des pages inféctés via XSS et d'autres qui ne le sont pas dans le but d'entrainer un classificateur .
Les données ont été récupérés via les sites suivants :

* [XSSED](http://www.xssed.com) : Une large base de données de pages HTML inféctés via XSS, à ce jour le site répértorie plus de 45.000 pages mirroirs .
* [DMOZ](https://www.dmoz.org/) : Un Directory qui contient des millions de sites web, les données ont été récupérés via la base de donné déja proposé par le site : [content.rdf.u8.gz](http://rdf.dmoz.org/rdf/content.rdf.u8.gz)

Le crawler en plus de récuperer un large ensemble de pages HTML (inféctés ou non) proposera aussi de les traiter en prélévant les features qui seront utilisés pour l'entrainement des classificateurs et leurs formatage en Matrices pour pouvoir les traiter beaucoup plus facilement via Matlab.

Le classificateur en question fera partie d'un autre projet (que je mettra aussi sur mon GitHub) il utilisera le [Support Vector Machine](https://fr.wikipedia.org/wiki/Machine_%C3%A0_vecteurs_de_support)

## Fichiers du projet
Le projet contient en gros 8 fichiers :

* **crawler.py** : Le programme principale .
* **crawl.conf** : Contient les parametres qui permettront de personaliser le crawler (taille du Dataset entre autres ).



