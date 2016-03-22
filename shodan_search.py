#!/usr/bin/env python
#
# shodan_ips.py
# Search SHODAN and print a list of IPs matching the query
#
# Author: achillean

import shodan
import sys
import codecs

# Configuration
API_KEY = "OefcMxcunkm72Po71vVtX8zUN57vQtAC"
output_file=""

def generate_output(filepath,message):
    f = open(filepath,"w+")
    f.writelines(message)
    f.close()

def safe_str(obj):
    """ return the byte string representation of obj """
    try:
        if type(obj) == unicode:
            return str(obj)
        else:
            return unicode(obj).encode('unicode_escape')
    except UnicodeEncodeError:
        # obj is unicode
        return unicode(obj).encode('unicode_escape')

def searchDict(pattern,myobj,output,key=""):
    if type(myobj) == dict:
        for k, v in myobj.iteritems():
            if key=="":
                searchDict(pattern,v,output,k)
            else:
                searchDict(pattern,v,output,key+"."+k)

    # TODO : print list properly
    elif type(myobj) == list:
        #print key+" : (list) "+str(myobj)
        if pattern in safe_str(myobj):
            #print str(key)+" = "+str(myobj)
            output = output + key+" = "+str(myobj)+"\n"
    else:
        #print key+" : (list) "+safe_str(myobj)
        if pattern in safe_str(myobj):
            #print key+" = "+safe_str(myobj)
            output = output + key+" = "+safe_str(myobj)+"\n"



# Input validation
if len(sys.argv) == 1:
    print 'Usage: %s <search query>' % sys.argv[0]
    sys.exit(1)

try:
    # Setup the api
    api = shodan.Shodan(API_KEY)

    # Perform the search
    query = ' '.join(sys.argv[1:])
    result = api.search(query)

    # Loop through the matches and print each IP
    for service in result['matches']:
        #print "############################# "+safe_str(service['hostnames'])+" | "+safe_str(service['ip_str'])+" ########################################"
        output_file = output_file + "############################# "+safe_str(service['hostnames'])+" | "+safe_str(service['ip_str'])+" ########################################"+"\n"
        searchDict(sys.argv[1],service,output_file)
        #break

        '''
        output_file = output_file + "\n" + \
                safe_str(service['ip_str']) + "\t" + \
                safe_str(service['os']) + "\t" + \
                safe_str(service['org']) + "\t" + \
                safe_str(service['domains']) +"\t" + \
                safe_str(service['hostnames'])

        '''

    #print safe_str(output_file)

except Exception as e:
    print 'Error: %s' % e
    sys.exit(1)

generate_output("/tmp/toto_0",output_file)
