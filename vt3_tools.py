import logging
import argparse
from datetime import datetime
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
    time1 = datetime.now()
    # Read values from input file
    values = ValueReader(args.input_file, args.values).read_values()
    if not values:
        logging.info("No values to analyze.")
        return
    # Analyze each value type
    for value_type in types:
        
        if not values[value_type]:
            logging.info(f"No {value_type} to analyze.")
            continue

        logging.info(f"Analyzing {len(values[value_type])} {value_type}...")
        results = analyze_value_type(init, value_type, values[value_type])

        if results:
            process_results(init, results, value_type)
        else:
            logging.info(f"No {value_type} to analyze.")
    csvfilescreated = list(set(init.output.csvfilescreated))
    logging.info("Analysis completed.")
    close_resources(init)
    time2 = datetime.now()
    total = time2 - time1
    logging.info(f"Analysis completed in {total} !")
    print("Thank you for using VT Tools ! ")
    misp_choice(case_str=str(args.case_id or 0).zfill(6),csvfilescreated=csvfilescreated)

def analyze_value_type(init, value_type, values):
    results = []
    for value in values:
        try:
            result = analyze_value(init, value_type, value)
            if result:
                results.append(result)
        except Exception as e:
            logging.error(f"Error analyzing {value_type}: {value}\n{e}")
    return results

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