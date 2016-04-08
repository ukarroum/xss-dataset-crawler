#!/usr/bin/python3

#############################################
# Auteur    :   Yassir Karroum 
#               [ukarroum17@gmail.com] 
#               [https://github.com/ukarroum]

# Description   : Un petit script qui déobfusc un code JS sans connaissance
#                 de l'encodage utilisé il support pour le moment quatres encodages : HTML reference Character (hex et dec), Unicode, base 64
#
#               Tout cela est fait de manière statique
#############################################

import re
import base64
import urllib.parse

def hex2str(code):
    
    items = re.findall("&#x[0-9A-Fa-f]{2};", code)
    for item in items:   
        code = code.replace(item, chr(int(item[3:-1], 16)))
        
    items = re.findall("\\\\x[0-9A-Fa-f]{2}", code)
    for item in items:   
        code = code.replace(item, chr(int(item[2:], 16)))
        
    return code

def dec2str(code):
    
    items = re.findall("&#[0-9]{2,3};", code)
    for item in items:   
        code = code.replace(item, chr(int(item[2:-1])))
    return code

def oct2str(code):

    items = re.findall("\\\\[0-9]{3}", code)
    for item in items:   
        code = code.replace(item, chr(int(item[1:], 8)))
        
    return code

def unicode2str(code):
     
    items = re.findall("\\\\u[0-9a-fA-F]{4}", code)
    for item in items:   
        code = code.replace(item, chr(int(item[2:], 16)))
        
    items = re.findall("\\\\U[0-9a-fA-F]{8}", code)
    for item in items:   
        code = code.replace(item, chr(int(item[2:], 16)))
        
    return code

def base642str(code):

    items = re.findall("base64,[0-9a-zA-Z+/=]+", code)
    for item in items:   
        code = code.replace(item, base64.b64decode(item[7:]).decode('utf-8'))
        
    return code
    
def url2str(code):
    return urllib.parse.unquote(code)

def charcode2str(code):
    
    while "String.fromCharCode" in code:
        pos = code.find("String.fromCharCode")
        hiddenStr = code[code.find("(", pos) + 1:code.find(")", pos)]
        hiddenStr = hiddenStr.split(',')
        hiddenStr = [ int(x) for x in hiddenStr ]
       
        code = code[:pos] + ''.join(map(chr, hiddenStr)) + code[code.find(")", pos) + 1:] 
    return code

def decode(code):
    return(charcode2str(hex2str(dec2str(oct2str(unicode2str(base642str(url2str(code))))))))
    
