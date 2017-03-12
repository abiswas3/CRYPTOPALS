import collections
import string

'''When a cipher text has been decoded, how do we know it's the right
plain text?  Well if the plain text was written using the rules of
english grammar, the distribution of letters tends to follow a
particular pattern. 

So given a decoding of a cipher text, can we come up with a scoring
function that outputs the likelihood that the plain text makes sense?

Determine the chi-squared value for the empirical distribution
compared to the true distribution
'''

def get_score(byte_arr):

    
    freq = {
        'a':8.2,
        'b':1.5,
        'c':2.8,
        'd':4.3,
        'e':12.7,
        'f':2.2,
        'g':2.0,
        'h':6.1,
        'i':7.0,
        'j':0.2,
        'k':0.8,
        'l':4.0,
        'm':2.4,
        'n':6.7,
        'o':7.5,
        'p':1.9,
        'q':0.1,
        'r':6.0,
        's':6.3,
        't':9.1,
        'u':2.8,
        'v':1.0,
        'w':2.4,
        'x':0.2,
        'y':2.0,
        'z':0.1,
    }

    lower_case = [i for i in range(ord('a'),ord('z'))]
    upper_case = [i for i in range(ord('A'),ord('Z'))]
    empirical_dist = collections.Counter(byte_arr)


    TRUE_DIST = {}
    
    for i in lower_case:
        TRUE_DIST[i] = freq[chr(i)]
        
    for i in upper_case:
        TRUE_DIST[i] = freq[chr(i).lower()]

    # punctuation = [ord(i) for i in list(string.punctuation)]
    punctuation = ['.',
                    ',',
                    "'",
                    '!',
                    '?',
                    ':',
                    '"',
                    ')',
                    '(',
                    ' ',
                    '\n']

    
    punctuation = [ord(i) for i in punctuation]

    count = 0
    # check if it has garbage characters that are not punctuation
    # penalise heavily
    for key in empirical_dist.keys():
        if key not in punctuation and key not in lower_case and key not in upper_case:
            count += 100
    

    for key in lower_case:
        empirical_num = 0
        expected_num = TRUE_DIST[key]*len(byte_arr)
        if key in empirical_dist.keys():
            empirical_num = empirical_dist[key]
        count += (empirical_num - expected_num)**2/(expected_num)
                        
    return count

