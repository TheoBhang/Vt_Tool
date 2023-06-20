''' Convert a VirusTotal report into MISP objects '''
# Revisited view of the https://github.com/MISP/PyMISP/blob/main/examples/vt_to_misp.py script
import csv
import logging
import os
from datetime import datetime
from urllib.parse import urlsplit
import pymisp
from pymisp.tools import VTReportObject
import re
import urllib3
urllib3.disable_warnings()
def generate_report(indicator, apikey):
    '''
    Build our VirusTotal report object, File object, and AV signature objects
    and link them appropriately

    :indicator: Indicator hash to search in VT for
    '''


def get_misp_event(misp, case_str):
    '''
    Smaller helper function for generating a new MISP event or using a preexisting one

    :event_id: The event id of the MISP event to upload objects to

    :info: The event's title/info
    '''
    event = pymisp.MISPEvent()
    event.distribution = 0
    event.threat_level_id = 2
    event.analysis = 2
    event.info = "Vt Tools Report - Case: " + case_str+ " - " + str(datetime.now())

    event = misp.add_event(event, pythonify=True)
    return event


def main(misp, case_str,csvfilescreated):
    '''
    Main program logic

    :misp: PyMISP API object for interfacing with MISP

    '''
    misp_event = get_misp_event(misp,case_str)
    
    for csvfile in csvfilescreated:
        hashmatch = re.search(r'Hashes', csvfile)
        urlmatch = re.search(r'URL', csvfile)
        ipmatch = re.search(r'IP', csvfile)
        f = open(csvfile, newline='')
        csv_reader = csv.reader(f, delimiter=";")
        
        
        reports = []
        if ipmatch:
            for line in csv_reader:
                ip = line[0]
                vt_score = line[1]
                owner = line[4]
                location = line[5]
                network = line[6]
                info = line[7]
                certif = line[8]
                permalink = line[9]
                if ip != "ip" and ip != "" :
                    print("Adding MISP object for " + ip)
                    misp_object = pymisp.MISPObject(name='domain-ip')
                    obj1 = misp_object.add_attribute("ip-src", value = ip, type="ip-src")
                    obj1.add_tag('tlp:green')
                    obj2 = misp_object.add_attribute("vt-score", value = vt_score, type="text", category="Antivirus detection")
                    obj2.add_tag('tlp:white')
                    obj3 = misp_object.add_attribute("owner", value = owner, type="text")
                    obj3.add_tag('tlp:white')
                    obj4 = misp_object.add_attribute("location", value = location, type="text")
                    obj4.add_tag('tlp:white')
                    obj5 = misp_object.add_attribute("network", value = network, type="text")
                    obj5.add_tag('tlp:white')
                    obj6 = misp_object.add_attribute("text", value = info, type="text")
                    obj6.add_tag('tlp:white')
                    obj7 = misp_object.add_attribute("certificate", value = certif , type="text")
                    obj7.add_tag('tlp:white')  
                    obj8 = misp_object.add_attribute("link", value = permalink , type="link")
                    obj8.add_tag('tlp:white')
                    r = misp.add_object(misp_event, misp_object)
                    reports.append(r)
        if urlmatch:
            for line in csv_reader:
                url = line[0]
                vt_score = line[1]
                metadatas = line[4]
                targeted = line[5]
                info = line[6]
                trakers = line[7]
                permalink = line[8]
                if url != "url" and url != "":
                    print("Adding MISP object for " + url)
                    misp_object = pymisp.MISPObject(name='url')
                    obj1 = misp_object.add_attribute("url", value = url, type="url")
                    obj1.add_tag('tlp:green')
                    obj2 = misp_object.add_attribute("vt-score", value = vt_score, type="text", category="Antivirus detection")
                    obj2.add_tag('tlp:white')
                    obj3 = misp_object.add_attribute("metadatas", value = metadatas, type="text")
                    obj3.add_tag('tlp:white')
                    obj4 = misp_object.add_attribute("targeted", value = targeted, type="text")
                    obj4.add_tag('tlp:white')
                    obj5 = misp_object.add_attribute("trackers", value = trakers, type="text")
                    obj5.add_tag('tlp:white')
                    obj6 = misp_object.add_attribute("text", value = info, type="text")
                    obj6.add_tag('tlp:white')
                    obj7 = misp_object.add_attribute("link", value = permalink , type="link")
                    obj7.add_tag('tlp:white')
                    r = misp.add_object(misp_event, misp_object)
                    reports.append(r)
        
        if hashmatch:
           for line in csv_reader:
                sha256 = line[0]
                vt_score = line[1]
                md5 = line[7]
                sha1 = line[8]
                ssdeep = line[9]
                info = line[10]
                permalink = line[11]
                if sha256 != "hash" and sha256 != "":
                    # SIZE + FILENAME
                    print("Adding MISP object for " + sha256)
                    misp_object = pymisp.MISPObject(name='file')
                    obj1 = misp_object.add_attribute("sha256", value = sha256, type="sha256")
                    obj1.add_tag('tlp:green')
                    obj2 = misp_object.add_attribute("md5", value = md5 , type="md5")
                    obj2.add_tag('tlp:white')
                    obj3 = misp_object.add_attribute("sha1", value = sha1, type="sha1")
                    obj3.add_tag('tlp:white')
                    obj4 = misp_object.add_attribute("vt-score", value = vt_score, type="text", category="Antivirus detection")
                    obj4.add_tag('tlp:white')
                    obj5 = misp_object.add_attribute("ssdeep", value = ssdeep, type="ssdeep")
                    obj5.add_tag('tlp:white')
                    obj6 = misp_object.add_attribute("text", value = info, type="text")
                    obj6.add_tag('tlp:white')
                    obj7 = misp_object.add_attribute("link", value = permalink , type="link")
                    obj7.add_tag('tlp:white')
                    r = misp.add_object(misp_event, misp_object)
                    reports.append(r)
        if reports:
            for report in reports:
                submit_to_misp(misp, misp_event, report)   
    


def submit_to_misp(misp, misp_event, misp_objects):
    '''
    Submit a list of MISP objects to a MISP event

    :misp: PyMISP API object for interfacing with MISP

    :misp_event: MISPEvent object

    :misp_objects: List of MISPObject objects. Must be a list
    '''
# go through round one and only add MISP objects
    for misp_object in misp_objects:
        misp.add_object(misp_event.id, misp_object)
    # go through round two and add all the object references for each object
            

  
def misp_event(case_str,csvfilescreated):
    try:
        print("Initialyzing MISP connection")
        print("Checking env variables...")
        misp_key = os.getenv("MISPKEY")
        misp_url = os.getenv("MISPURL")
        if not misp_url:
            print("No MISPURL env variable found, please set it")
            misp_url = input("Enter your MISP url : ")
        if not misp_key:
            print("No MISPKEY env variable found, please set it")
            misp_key = input("Enter your MISP key : ")
        misp = pymisp.ExpandedPyMISP(misp_url, misp_key, False)
        # finally, let's start checking VT and converting the reports
        main(misp, case_str,csvfilescreated)
    except KeyboardInterrupt:
        print("Bye")
    except pymisp.exceptions.InvalidMISPObject as err:
        logging.error(err)

    
        
def mispchoice(case_str, csvfilescreated):
    print("Do you want to send the results to MISP ?")
    print("Yes (1,Y,y,YES,yes)")
    print("No (2,N,n,NO,no)")
    try:
        choice = input("Enter your choice : ")
    except:
        print("Can't input choice. Docker version enabled.")
        choice = "1"
    if choice == "1" or choice == "Y" or choice == "y" or choice == "YES" or choice == "yes" or choice == "^[[B":
        misp_event(case_str, csvfilescreated )
    elif choice == "2" or choice == "N" or choice == "n" or choice == "NO" or choice == "no" or choice == "^[[F":
        print("MISP event not created")
    else:
        print("Wrong choice, retrying...")
        mispchoice(case_str, csvfilescreated)
    