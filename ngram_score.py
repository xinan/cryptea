#!/usr/bin/env python3
# http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/

from math import log10

class ngram(object):
  def __init__(self, ngramfile, sep=' '):
    self.ngrams = {}
    with open(ngramfile) as f:
      for line in f.readlines():
        key, count = line.split(sep) 
        self.ngrams[key] = int(count)
    self.L = len(key)
    self.N = sum(self.ngrams.values())
    for key in self.ngrams.keys():
      self.ngrams[key] = log10(float(self.ngrams[key]) / self.N)
    self.floor = log10(0.01 / self.N)

  def score(self, text):
    score = 0
    ngrams = self.ngrams.__getitem__
    for i in range(len(text) - self.L + 1):
      if text[i:i + self.L] in self.ngrams: 
        score += ngrams(text[i:i + self.L])
      else: 
        score += self.floor          
    return score
    
monogram_scorer = None
bigram_scorer = None
trigram_scorer = None
quadgram_scorer = None
quintgram_scorer = None
     
def monogram_score(t):
  global monogram_scorer;
  if not monogram_scorer:
    monogram_scorer = ngram('ngrams/english_monograms.txt')
  return monogram_scorer.score(t.decode('ISO-8859-1').replace(' ', '').upper())
  
def bigram_score(t):
  global bigram_scorer;
  if not bigram_scorer:
    bigram_scorer = ngram('ngrams/english_bigrams.txt')
  return bigram_scorer.score(t.decode('ISO-8859-1').replace(' ', '').upper())
  
def trigram_score(t):
  global trigram_scorer;
  if not trigram_scorer:
    trigram_scorer = ngram('ngrams/english_trigrams.txt')
  return trigram_scorer.score(t.decode('ISO-8859-1').replace(' ', '').upper())
  
def quadgram_score(t):
  global quadgram_scorer;
  if not quadgram_scorer:
    quadgram_scorer = ngram('ngrams/english_quadgrams.txt')
  return quadgram_scorer.score(t.decode('ISO-8859-1').replace(' ', '').upper())
  
def quintgram_score(t):
  global quintgram_scorer;
  if not quintgram_scorer:
    quintram_scorer = ngram('ngrams/english_quintgrams.txt')
  return quintgram_scorer.score(t.decode('ISO-8859-1').replace(' ', '').upper())
