import logging
import argparse
from datetime import datetime
import requests
import os
from dotenv import load_dotenv
from app.MISP.vt_tools2misp import misp_choice
from init import Initializator
from app.FileHandler.create_table import CustomPrettyTable as cpt
from app.FileHandler.read_file import ValueReader
from app.DataHandler.utils import get_api_key, get_proxy, get_user_choice

def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Print welcome message
    print_welcome_message()

    # Parse command-line arguments
    args = parse_arguments()

    # Get user choice for value type
    value_type = get_user_choice()

    # Analyze values
    analyze_values(args, value_type)
    
def get_remaining_quota(api_key: str, proxy: str = None): 
    """Returns the number of hashes that could be queried within this run""" 
    url = f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas" 
    headers = {"Accept": "application/json", "x-apikey": api_key} 

    # Get the quotas, if response code != 200, return 0 so we don't query further 
    response = requests.get(url, headers=headers, proxies={"http": proxy, "https": proxy}) 
    if response.status_code == 200: 
        json_response = response.json() 
    else: 
        print( 
            "Error retrieving VT Quota (HTTP Status code: %d)", response.status_code 
        ) 
        return 0
    # Get the number of remaining queries
    allowed_hourly_queries = json_response["data"]["api_requests_hourly"]["user"]["allowed"]
    used_hourly_queries = json_response["data"]["api_requests_hourly"]["user"]["used"]
    remaining_queries = allowed_hourly_queries - used_hourly_queries
    return remaining_queries


def print_welcome_message():
    welcome_message = """
       ^77777!~:.                 :~7?JJJJ?!.     
       :!JYJJJJJ?!:            .~?JJJJJYJ?!^.     
         .!JYJJJJYJ!.         .!!7?JJJJ~:         
.~:        .!JJJJJJY7         77  ~JJJ~           
~YJ7:      :7JJJYJJJY~        7?!!?7!J7.        :^
7JJJJ7:  ^7JJJ7:~?JJY!        :JYY??JYY?^.  .^!?JJ
^JJYJ7:^?JJJ7:~?~:?JJ^       ^?JJJ!^^~~JY?7?JJYJY?
 !J!:^?JJJ!:!?~:?JJJJ?~.  .^?JJJJJJ! ~??J:.~JJJY?:
  .:?YYJJJJ?~^JJJJJJJJY?~.^JYJJJJJJJ?JJ?J!~~JJ7^  
   .^!?JJJYYYJJJJJJJJJ7:7J!:~?YJJJYJ7::^~~~~:.    
       .:^^^^:^7JJJJJJ: 7YYJ!:^?JJ!:              
                :7JYJ~ :!~~~!J!:^.                
                .^:!J!!^:~~~!?JJ7:                
              :7JJ?^:!J^:~JYY~.~?Y7^              
            :7JYJJJY?~:~?JJJJ~ ..:7J?^            
     .::^^^7JJJJJJJJJY?:.~JJ^.~??^!JJJ?^          
  .~?JYYYJJYJJJJJJJJJ7^   .~?7.^JJYJJJJJ?~.       
 ~JJ7!!!^. !YYJJJJJ7:       .^77:^7?JJJJJY?~.     
!YJJ.       ^~7JJ7:            ^7~.7J?JJJJJYJ!.   
JJJ!          ^JY~               ^~7^~JJJJJJJJJ!. 
JY7.         ~YJY^                 :!JYJJJ^...~JJ^
^JJJ7^    .  !YY7                    :7JY?     ?Y7
 :7JYY!:~????J?~                       :!J?~~!7J?.
   :~7JJYJJ?7^.                          .~7?7!^     
   
  _      __      __                        __          _   __ __    ______            __   
 | | /| / /___  / /____ ___   __ _  ___   / /_ ___    | | / // /_  /_  __/___  ___   / /___
 | |/ |/ // -_)/ // __// _ \ /  ' \/ -_) / __// _ \   | |/ // __/   / /  / _ \/ _ \ / /(_-<
 |__/|__/ \__//_/ \__/ \___//_/_/_/\__/  \__/ \___/   |___/ \__/   /_/   \___/\___//_//___/
 
  _           _____ _  _   _       ___ ___ ___ _____  
 | |__ _  _  |_   _| || | /_\ ___ / __| __| _ \_   _| 
 | '_ \ || |   | | | __ |/ _ \___| (__| _||   / | |   
 |_.__/\_, |   |_| |_||_/_/ \_\   \___|___|_|_\ |_|   
       |__/                                          
 
 
 Welcome to the VirusTotal analysis tool by THA-CERT! 
 
 This script will retrieve analysis information for a set of values (IP/Hash/URL/Domains) from VirusTotal. 
 To use the tool, provide your VirusTotal API key and the values you want to analyze. 
 The tool supports input from various sources, including files, standard input, and command line arguments.
 
        Usage: vt3_tools.py [OPTIONS] VALUES...

        Retrieve VirusTotal analysis information for a set of values (IP/Hash/URL/Domains).

 """
    print(welcome_message)

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", "-f", type=str, help="Input file containing values to analyze.")
    parser.add_argument("--case_id", "-c", type=str, help="ID for the case to create (Or MISP event UUID to create or update)")
    parser.add_argument("--api_key", "-a", type=str, help="VirusTotal API key, default VTAPIKEY env var")
    parser.add_argument("--api_key_file", "-af", type=str, help="VirusTotal API key in a file.")
    parser.add_argument("--proxy", "-p", type=str, help="Proxy to use for requests.")
    parser.add_argument("values", type=str, nargs="*", help="The values to analyze. Can be IP addresses, hashes, URLs, or domains.")
    return parser.parse_args()

def analyze_values(args, types):

    
    # Load environment variables
    load_dotenv()

    # Initialize components
    init = Initializator(get_api_key(args.api_key, args.api_key_file), get_proxy(args.proxy), str(args.case_id or 0).zfill(6))
    
    # create or search for an sqlite database
    database = "vttools.sqlite"
    quota_saved = 0
    # Create a database connection
    conn = init.db_handler.create_connection(database)

    # Create tables
    if conn is not None:
        init.db_handler.create_schema(conn)
        
    time1 = datetime.now()
    # Read values from input file
    print("\n")
    print("Checking for remaining queries...")
    
    remaining_queries = get_remaining_quota(init.api_key, init.proxy)
    if remaining_queries == 0:
        logging.info("No remaining queries. Exiting...")
        logging.info("Check your API key before analysis.")
        print("Thank you for using VT Tools ! ")
        return
    logging.info(f"Remaining queries for this hour: {remaining_queries}")
    print("\n")
    values = ValueReader(args.input_file, args.values).read_values()
    print("\n")
    print(f"This analysis will use {len(values)} out of your {remaining_queries} hourly quota.")
    print("\n")
    if remaining_queries < len(values):
        logging.info("Not enough remaining queries to analyze all values.")
        logging.info("Please try again later or with a different API key.")
        print("Thank you for using VT Tools ! ")
        return
    if not values:
        logging.info("No values to analyze.")
        print("Thank you for using VT Tools ! ")
        return
    # Analyze each value type
    for value_type in types:
        
        if not values[value_type]:
            logging.info(f"No {value_type} to analyze.")
            continue

        logging.info(f"Analyzing {len(values[value_type])} {value_type}...")
        results, skipped_values = analyze_value_type(init, value_type, values[value_type],conn)
        quota_saved += skipped_values
        if results:
            process_results(init, results, value_type)
        else:
            logging.info(f"No {value_type} to analyze.")
    csvfilescreated = list(set(init.output.csvfilescreated))
    print("\n")
    print(f"Analysis completed. {quota_saved} values were skipped as they already exist in the database.")
    print("\n")
    
    quota_final = get_remaining_quota(init.api_key, init.proxy)
    print(f"Remaining queries for this hour: {quota_final}")
    print("\n")    
    close_resources(init)
    time2 = datetime.now()
    total = time2 - time1
    logging.info(f"Analysis completed in {total} !")
    print("Thank you for using VT Tools ! ")
    misp_choice(case_str=str(args.case_id or 0).zfill(6),csvfilescreated=csvfilescreated)

def analyze_value_type(init, value_type, values, conn):
    results = []
    skipped_values = 0
    for value in values:
        # Check if value exists in the database
        if value_exists(init,value,value_type, conn):
            logging.info(f"Skipping analysis for {value_type}: {value} (already exists in the database)")
            if value_type == "hashes":
                value_type_str = init.validator.validate_hash(value)
            else:
                validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
                value_type_str = validator_func(value)
                
            if value_type_str:
                if value_type_str not in ["Private IPv4", "Loopback IPv4", "Unspecified IPv4", "Link-local IPv4", "Reserved IPv4","SHA-224","SHA-384","SHA-512", "SSDEEP"]:
                    try:
                        results.append(init.db_handler.get_report(value, value_type_str.upper(), conn))
                    except Exception as e:
                        logging.error(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
            skipped_values += 1    
        else:
            logging.info(f"Analyzing {value_type}: {value}")
            try:
                result = analyze_value(init, value_type, value)
                if result:
                    results.append(result)
            except Exception as e:
                logging.error(f"Error analyzing {value_type}: {value}\n{e}")
    return results, skipped_values

def value_exists(init,value, value_type, conn):

    if value_type == "hashes":
        return init.db_handler.hash_exists(value, conn)
    elif value_type == "urls":
        return init.db_handler.url_exists(value, conn)
    elif value_type == "domains":
        return init.db_handler.domain_exists(value, conn)
    elif value_type == "ips":
        return init.db_handler.ip_exists(value, conn)
    else:
        return False

def analyze_value(init, value_type, value):
    if value_type == "hashes":
        value_type_str = init.validator.validate_hash(value)
    else:
        validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
        value_type_str = validator_func(value)
        
    if value_type_str:
        if value_type_str not in ["Private IPv4", "Loopback IPv4", "Unspecified IPv4", "Link-local IPv4", "Reserved IPv4","SHA-224","SHA-384","SHA-512", "SSDEEP"]:
            try:
                return init.reporter.get_report(value_type_str.upper(), value)
            except Exception as e:
                logging.error(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
    else:
        logging.error(f"Invalid {value_type[:-1]}: {value}")
    return None

def process_results(init, results, value_type):
    header_rows = []
    value_rows = []
    for result in results:
        for row in result["rows"]:
            if row[0] not in header_rows:
                header_rows.append(row[0])
            value_rows.append(row[1:])

    table = cpt(header_rows, value_rows)
    strtable = table.create_table()

    total_csv_report = [result["csv_report"] for result in results]
    init.output.output_to_csv(total_csv_report, "HASH" if value_type == "hashes" else value_type[:-1].upper())

    init.output.output_to_txt(strtable, "HASH" if value_type == "hashes" else value_type[:-1].upper())
    printval="HASH" if value_type == "hashes" else value_type[:-1].upper()
    logging.info(f"{printval} Analysis ended successfully")

def close_resources(init):
    init.client.close()

if __name__ == '__main__':
    main()