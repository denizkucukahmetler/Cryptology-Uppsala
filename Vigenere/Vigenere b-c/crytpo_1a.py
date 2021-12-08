#!/usr/bin/python3
# -*- coding: utf-8 -*-
import math

text_file = open("text.txt")
text = text_file.read()
#Letter Frequencies for Swedish Alphabet
#SOURCE: 
freq = {"a": 10.04, "b": 1.31, "c": 1.71, "d": 4.90, "e": 9.85, "f": 1.81, "g": 3.44, "h": 2.85, "i": 5.01, "j": 0.90, "k": 3.24, "l": 4.81, "m": 3.55, "n": 8.45, "o": 4.06, "p": 1.57, "q": 0.01, "r": 7.88, "s": 5.32, "t": 8.89, "u": 1.86, "v": 2.55, "w": 0.05 ,"x": 0.11, "y": 0.49, "z": 0.04, "å": 1.66, "ä": 2.10, "ö": 1.50}

#Function for creating the letters as a list 
def letters():
    #Pre-condition: N/A
    #Post-condidtion: A list of characters sorted by their position in the alphabet
    letter_list = []
    for k in freq:
        letter_list.append(k)
    return letter_list

letter_list = letters() #["a", "b", "c", ...]

#Function for finding index of coincidence for every letter in Swedish, based on their frequencies. 
#Formula => IC(x) = sum of all (p_i)^2 (0<=i<=28)
def swedish_index_of_coincidence():
    #Pre-condition: N/A
    #Post-condition: IC is a sum over index of coincidence for swedish letter frequencies

    #creating a string of Swedish alphabet according to frequencies (letter "a" has a frequency of 10.04, it will appear 1004 times, while "j" with frequency 0.90 will appear 90 times)
    strtest = ""
    for k,v in freq.items():
        strtest += k * int(v*100)

    #calculating overall index of coincidence, taking every letter into account 
    IC = 0
    for k,v  in freq.items():
        p_i = v*(100/len(strtest))
        IC +=( p_i)**2
    return IC


############################################                     FRIEDMAN TEST BEGINS               #############################################################
#x => ciphertext
#mm = m' => possible key length
#l = n/m'

def key_length(x):
    #Pre-condition: x is a string
    #Post-condition: i is the best key length found in x  
    len_dic = {}
    swedish = swedish_index_of_coincidence()

    #IC^m' (average of IC) will be close to Swedish index of coincidence
    #below is for finding the closest valued key length 
    for t in range(1,17):
        len_dic[t] = abs(swedish - ave(t, x))
    
    min_v = min(len_dic.values())
    for i in len_dic.keys():
        if len_dic[i] == min_v:
            return i

#Nested functions in order to find the key length:


def ave(mm, x):  #taking the average of index of coincidences (IC^m')
    #Precondition: mm is a postive integer, x is a string
    #Postcondition: total is the average of index of coincidences
    total = 0
    for i in range(1, mm+1):
        add = x_j(x, i , mm)
        total += IC(add, len(x)/mm)

    total = total/mm
    return total

def IC(x, l): #computing each index of coincidence
    #Pre-condition: x is a string, l is a positive integer
    #Post-condition: total is the index of coincidence for length l
    total = 0
    for i in freq.keys():
        total += occur(x, i)*(occur(x,i)-1)/(l*(l-1))

    return total


def occur(x_j, i): #calculating number of occurences of i in x_j
    #Pre-condition: x_j is a string, i is a character
    #Post-condition: count is the amount of occurences of letter i in x_j
    count = 0 
    for ch in x_j:

        if ch == i:
            count +=1 
    
    return count


def x_j(x, j, mm): #x^j = x_j+ x_(j+m')+ x_(j+2m')..... (1<=j<=m')
    #Pre-condition: x is a string, j is a positive integer and mm is a positive integer
    #Post-condition: text is the periodic sum of all the characters 
    text = ""
    for i in range(j, len(x), mm):
        text += x[i]

    return text #x^j is returned



############################################                     FRIEDMAN TEST ENDS                 ####################################################################


def freq_analysis(key_length, text):
    #Pre-condition: key_length is a positive integer, text is a string
    #Post-condition: key_text is a string resembling the key for encryption of text 
    key_text = ""
    swedish = swedish_index_of_coincidence()

    l = len(text)/key_length

    #loop for finding the key character by character
    for ch in range(key_length):

        kj = {} #all possible key characters will be kept in the dictionary

        for j in range(29):
            total = 0
            x = x_j(text, ch, key_length)

            #finding p_i 
            strtest = ""
            for k,v in freq.items():
                strtest += k * int(v*100)
            
            #calculating all possible values of shifted frequencies and adding to the dictionary
            for key,value in freq.items():
                p_i = value *(100/len(strtest))
                
                i = (letter_list.index(key)+j)%29 
                
                total += p_i*occur(x,letter_list[i])/l
            kj[letter_list[j]] = total


        optimum_value = 500 

        #finding the key character most closest to swedish frequency distribution
        for k,v in kj.items():
            diff = abs(v-swedish)
            if diff<optimum_value: #update if a better character is found
                optimum_value = diff
                optimum_ch = k
        key_text += optimum_ch

    return key_text #generated key is returned


#Function for decrypting a given cipher text and a key
def decrption(text,key):
    #Pre-condition: text is a string, key is a string
    #Post-condition: decrypted_text is a string based on decrptying text based on key
    lent = len(text) #length of the ciphertext
    lenk = len(key)  #length of the plaintext 

    #string created with repetitive key, the length is equal to the cipher text length 

    remainder = lent % lenk  
    iter = int((lent - remainder)/lenk) 
               
    key = iter * key + key[0: remainder]

    decrypted_text = ""

    #reverse of encryption operation
    for x in range(len(key)):
        text_ch =letter_list.index(text[x])    
        key_ch = letter_list.index(key[x])
        decrypted_text += letter_list[( text_ch- key_ch )%29]  
    

    return decrypted_text, text


key_l = key_length(text)
key = freq_analysis(key_l, text)
print("Key length is:", key_l)
print("Key is:", key)
print("Decrypted text is: ",decrption(text, key))

text_file.close()