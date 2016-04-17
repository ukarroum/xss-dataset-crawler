import pickle
import re
import deobfusc
from collections import Counter

websites = pickle.load(open("xss_dataset.pickle", "rb"))

wordfreq = []

for url, website in websites["xssed"][1:100]:
    print(url)
    wordlist = re.split(" |<|>|'|\"|[|]|\\n|\\t|\\r|/>|/|\\.", deobfusc.decode(website)) + re.split(" |<|>|'|\"|[|]|\\n|\\t|\\r|/>|/|\.", deobfusc.decode(url)) 
    wordfreq += Counter(wordlist).most_common(100)
    
wordfreq.sort()
print(wordfreq)
