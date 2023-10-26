#encoding: utf-8
"""
 Fetches data from VT based on multiple values such as Hash, Ip, Domain or Urls
 and adds the data into two files for each categories of Objects
 - CSV File containing the data
 - TXT File containing the table with more readable datas
---
MIT License

Copyright (c) 2023 Theo Bhang (THA-CERT https://github.com/thalesgroup-cert)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse                     # for parsing command line arguments
from datetime import datetime      # for getting the current date and time
import logging                      # for logging the script's activity
from dotenv import load_dotenv     # for loading environment variables

from app.MISP.vt_tools2misp import mispchoice # for interacting with MISP
from init import Initializator # for initializing the script
from app.FileHandler.create_table import PrettyTable # for creating tables
from app.FileHandler.read_file import ValueReader # for reading values from a file
from app.DataHandler.utils import get_api_key, get_proxy, get_user_choice # for interacting with the operating system
        


def analyze_values(args, types):
    """
    Analyze values.

    Parameters:
    args (Namespace): The arguments passed to the script.
    """
    table_values = []
    if types:
        table_values.append(types)
    else:
        table_values = ["ips", "domains", "urls", "hashes"]
    load_dotenv()
    api_key = get_api_key(args.api_key, args.api_key_file)
    proxy = get_proxy(args.proxy)
    case_number = str(args.case_id or 0).zfill(6)
    print(f"Begining case : #{case_number} ...\n")

    init = Initializator(api_key, proxy, case_number)
    time1 = datetime.now()

    # Get the values to analyze
    values = ValueReader(args.input_file, args.values).read_values()
    if not values:
        print("No values to analyze.")
        exit()

    # Analyze each value type
    results = {}
    for value_type in table_values:
        if not values[value_type]:
            print(f"No {value_type} to analyze.\n")
            continue

        print(f"Analyzing {len(values[value_type])} {value_type}...\n")
        value_results = []
        for value in values[value_type]:
            try:
                if value_type == "hashes":
                    value_type_str = init.validator.validate_hash(value)
                else:
                    validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
                    
                    value_type_str = validator_func(value)
                if value_type_str:
                    if value_type_str in ["Private IPv4", "Loopback IPv4", "Unspecified IPv4", "Link-local IPv4", "Reserved IPv4", "MD5","SHA-1","SHA-224","SHA-384","SHA-512", "SSDEEP"]:
                        continue
                    else:
                        try:
                            value_results.append(init.reporter.get_report(value_type_str.upper(), value))
                        except Exception as e:
                            print(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
                else:
                    print(f"Invalid {value_type[:-1]}: {value}\n")
            except Exception as e:
                print(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
        # Filter out invalid values
        value_results = [result for result in value_results if result]

        # Output the results
        if value_results:
            # Create the table of results
            header_rows = []
            value_rows = []
            for result in value_results:
                for row in result["rows"]:
                    if row[0] not in header_rows:
                        header_rows.append(row[0])
                    value_rows.append(row[1:])
            table = PrettyTable(header_rows, value_rows)
            strtable = table.create_table()

            total_csv_report = [result["csv_report"] for result in value_results]
            init.output.output_to_csv(total_csv_report, "HASH" if value_type == "hashes" else value_type[:-1].upper())

            # Output the results to a TXT file
            init.output.output_to_txt(strtable, "HASH" if value_type == "hashes" else value_type[:-1].upper())
            print(f"{value_type[:-1].upper()} Analysis ended successfully")
        else:
            print(f"No {value_type} to analyze.\n")

        results[value_type] = value_results

    # Close the VirusTotal client
    init.client.close()
    csvfilescreated = list(set(init.output.csvfilescreated))
    time2 = datetime.now()
    total = time2 - time1
    print(f"Analysis done in {total} !")
    print("Thank you for using VT Tools ! ")
    mispchoice(case_number, csvfilescreated)
    for csvfile in csvfilescreated:
        print(f"CSV file created : {csvfile}")

    


if __name__ == '__main__':
    a = """

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
 """
    b = """
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
    print(a, b)
    
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", "-f", type=str, help="Input file containing values to analyze.")
    parser.add_argument("--case_id", "-c", type=str, help="Id for the case to create")
    parser.add_argument("--api_key", "-a", type=str, help="VirusTotal API key, default VTAPIKEY env var.")
    parser.add_argument("--api_key_file", "-af", type=str, help="VirusTotal API key in a file.")
    parser.add_argument("--proxy", "-p", type=str, help="Proxy to use for requests.")
    parser.add_argument("values", type=str, nargs="*", help="The values to analyze. Can be IP addresses, hashes, URLs, or domains.")
    args = parser.parse_args()

    value_type = get_user_choice()

    analyze_values(args, value_type)

            
