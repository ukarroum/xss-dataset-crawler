import pickle
import re
import deobfusc
from collections import Counter

websites = pickle.load(open("xss_dataset.pickle", "rb"))

wordfreq = []
wordfreqUniq = []

for url, website in websites:
    wordlist = re.split(" |<|>|'|\"|[|]|\\n|\\t|\\r|/>|/|\\.", deobfusc.decode(website)) + re.split(" |<|>|'|\"|[|]|\\n|\\t|\\r|/>|/|\.", deobfusc.decode(url)) 
    wordfreq += Counter(wordlist).most_common(100)

i = 0
wordfreq.sort()

for word in wordfreq:
    if(len(wordfreqUniq) == 0):
        wordfreqUniq.append(list(word)) #Je transforme la tuple en liste d'abord puisqu'il n'est pas possible d'affecter une valeur a un element de tuple
        continue
    if(word[0] == wordfreqUniq[i][0]):
        wordfreqUniq[i][1] += word[1]
    else:
        wordfreqUniq.append(list(word))
        i += 1

wordfreqUniq = sorted(wordfreqUniq, key=lambda x: x[1], reverse=True) #Je trie par rapport à la deuxieme clé

for word in wordfreqUniq[1:1000]:
    print(word)
