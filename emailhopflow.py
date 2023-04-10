import mailparser
import json
import re
import ipinfo
from tabulate import tabulate
import os
from copy import deepcopy
from termcolor import colored
import argparse
import csv
import time
import textwrap


# The ipinfo.io API token
API_TOKEN = ""

def join_tuple_string(strings_tuple) -> str:
    """
        Convert a tuple to a string

    Args:
        strings_tuple (<tuple>): The tuple pair to be joined

    Returns:
        str: The two tuple values separated by -
    """
    return ' - '.join(strings_tuple)

def general_info_colored(prefix, value):
    return "{} {}".format(colored(str(prefix)+":","green"),value)

def parse_accordingly(prefix, value):
    return value if args.csv else general_info_colored(prefix, value)

# Declare argument variables
parser = argparse.ArgumentParser(
                    prog = 'mailflow_tool.py',
                    description = 'A simple cli tool to track multiple email messages - showing general info and hops')
#parser.add_argument('--hop',
#            action='store',
#            default="with,date_utc,delay",
#            help="Comma delimited list of keys to show in each hop info (DEFAULT: with,date_utc,delay)")
parser.add_argument('--general',
            action='store',
            default="file_name,id,subject,date,from,spf,dkim,dmarc,rcv_spf,total_delay",
            help="Comma delimited list of keys to show in each email general info - Ignored if in aggr mode (DEFAULT: file_name,id,subject,date,from,spf,dkim,dmarc,rcv_spf,total_delay)")
parser.add_argument('--csv',
            action='store_true',
            default=False,
            help="Add this flag if you would like to export data to csv, field filters will be applied - Ignored if in aggr mode")
parser.add_argument('--aggr',
            action='store_true',
            default=False,
            help="Add this flag if you would like to aggregate email by root domains")
parser.add_argument('--senderdomain',
            action='store',
            default="",
            help="Add this flag if you would like to aggregate for one domain only")
parser.add_argument('--iploc',
            action='store_true',
            default=False,
            help="Add this flag if you would like to add the src country ip location to the hop details - ipinfo.io API key is required")
parser.add_argument('--emailFolder',
            action='store',
            default=os.path.join(os.path.dirname(__file__),"emails"),
            help="The path to the emails folder, will fail if not exists (DEFAULT: {})".format(os.path.join(os.path.dirname(__file__),"emails")))
parser.add_argument('--csvFolder',
            action='store',
            default=os.path.join(os.path.dirname(__file__),"csv"),
            help="The path to where output the csv files, will create if not existent and csv mode selected (DEFAULT: {})".format(os.path.join(os.path.dirname(__file__),"emails")))


# Parse arguments and perform validity checks

args = parser.parse_args()

# Split the field lists by comma
#hop_args = args.hop.split(",")
general_args = args.general.split(",")

# The width of the console, will be used for relative column printing in console mode
console_width = os.get_terminal_size().columns

# set aggregate filter domain
if(args.senderdomain):
    sender_domain = args.senderdomain
else:
    # will be used as False bool value to indicate, that script should aggregate for all domains
    sender_domain = ""
# If ip location mode selected
if(args.iploc):
    # Check if api token defined and initialize the handler, else raise an error
    if("API_TOKEN" in locals() and API_TOKEN != None and API_TOKEN != ""):
        handler = ipinfo.getHandler(API_TOKEN)
    else:
        raise ValueError("No API token specified, can't extract ip location")

if(args.aggr): args.csv = False

# Check if emails path exists
emails_path = args.emailFolder
if(not os.path.exists(emails_path)):
    raise ValueError("No {} directory".format(emails_path))

# The table rows variable - represents console table or csv file rows
output_rows = []
aggr_dict = {}

def insert_auth_result_placeholder(filename):
    fh = open(filename)
    fhread = fh.readlines()
    findz = "Authentication-Results:"
    
    is_present = False
    for line in fhread:
        if line.startswith(findz):
            is_present = True
            break
    #print saved
    #spose = line.find('', atpos)

    if (not is_present):
        previous_text = ""
        for i in fhread:
            previous_text += i
        open(filename, "w").write("Authentication-Results: INTERNAL_PLACEHOLDER\n" + previous_text)
    fh.close()    


# Loop through all the email files in the path
for filename in os.listdir(emails_path):
    # Set full file name
    file_name = os.path.join(emails_path, filename)

    try:
        # inserting extra fields for internal emails if required
        insert_auth_result_placeholder(file_name)

        # Open the email file
        with open(file_name,encoding="utf-8") as fil:
            file_lines = fil.readlines()

        # Open the email file
        with open(file_name,encoding="utf-8") as fil:
            read_stream = fil.read()
        

        mail = mailparser.parse_from_string(read_stream)

        
        # The mail info dictionary 
        info_dict = {}

        # The general info property (non hop related data)
        info_dict["General Info"] = {}

        # Get the authentication header content
        authentication = json.loads(mail.headers_json)["Authentication-Results"]
        
        if(not args.aggr): # If not in aggregate mode (csv/normal)

            # The parameters for both csv and normal mode are very simillar - just a question of coloring and ; or line break
            join_char = ";" if args.csv else "\n"

            info_dict["General Info"]["file_name"] = parse_accordingly("File name",filename)
            info_dict["General Info"]["id"] = parse_accordingly("Message-ID",mail.message_id)
            info_dict["General Info"]["subject"] = parse_accordingly("Subject",mail.subject)
            info_dict["General Info"]["date"] = parse_accordingly("Date",mail.date)

            # The to property is in pairs (name - address), join the pairs and append to one list
            info_dict["General Info"]["to"] = parse_accordingly("To",join_char.join(list(map(join_tuple_string, mail.to))))
            
            # The from property is in pairs (name - address), join the pairs and append to one list
            info_dict["General Info"]["from"] = parse_accordingly("From",join_char.join(list(map(join_tuple_string, mail.from_))))
            
            # Find for each protocol the status from the auth header
            info_dict["General Info"]["spf"] = parse_accordingly("SPF",";".join(re.findall("(?<=spf=).*",authentication)))
            info_dict["General Info"]["dkim"] = parse_accordingly("DKIM",";".join(re.findall("(?<=dkim=).*",authentication)))
            info_dict["General Info"]["dmarc"] = parse_accordingly("DMARC",";".join(re.findall("(?<=dmarc=).*",authentication)))
            
            # Parse the received-spf header from the raw email content using regex
            spf_pattern = re.compile("(Received-SPF:(?s:.*?)(?=\\nReceived:))", re.VERBOSE | re.MULTILINE)
            matches = spf_pattern.findall(read_stream)

            # Remove line breakers 
            matches = [string.replace("\n","") for string in matches ]
            
            # If not in csv mode we should color the Received-SPF: words
            replace_to = "Received-SPF:" if args.csv else colored("Received-SPF:","green")
            info_dict["General Info"]["rcv_spf"] = (join_char.join(matches)).replace("Received-SPF:",replace_to)
        else: # If in aggregate mode
            info_dict["General Info"]["file_name"] = filename

            # The from property is in pairs (name - address), join the pairs and append to one list
            info_dict["General Info"]["from"] = mail._from[0][1].split("@")[1]


        # The total delay variable - will be the sum of all hop delays
        total_delay = 0.0

        # Initialize the hop info properties, relevant for console mode
        info_dict["Hops"] = []

        # Initialize the hop dictionary, relevant for csv mode
        hop_dict = {}


        # Loop through all hops
        for hop in json.loads(mail.received_json):
            # Set a dictionary key for each hop: hop1,hop2,...
            hop_dict["hop{}".format(hop["hop"])] = {}
            hop_obj = hop_dict["hop{}".format(hop["hop"])]

            hop_obj["serial"] = hop["hop"]

            # Find the source and destination using a '<fqdn>(0 or more) <ip>' regex
            try:
                hop_obj["from"] = re.findall("(((?=.{4,253}\.?$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?)\s*)*\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})*)",hop["from"])[0][0]
            except:
                hop_obj["from"] = ""
            try:
                hop_obj["by"] = re.findall("(((?=.{4,253}\.?$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?)\s*)*\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})*)",hop["by"])[0][0]
            except:
                hop_obj["by"] = ""
            
            if(not args.aggr):
                hop_obj["date_utc"] = hop["date_utc"]
                hop_obj["delay"] = hop["delay"]

                
                # If ip location mode enabled and the hop has a from header
                if(args.iploc and 'from' in hop.keys()):
                    # Get only the ipv4 pattern
                    ips = re.findall('(?:[0-9]{1,3}\.){3}[0-9]{1,3}',hop['from'])

                    # Loop through all the ips and get their countries
                    country = []
                    for ip in ips:
                        try:
                            country.append(handler.getDetails(ip).country)
                        except: # If no country found
                            country.append("iplocation fail")
                    hop_obj["country"] = ";".join(country)


                # Sum up the total delay
                total_delay += float(hop["delay"])
            else:
                for key in ["from","by"]:
                    try:
                        first_word = hop_obj[key].split(" ")[0]
                        hop_obj[key] = re.findall("\w+\.\w+$",first_word)[0]
                    except:
                        hop_obj[key] = hop_obj[key]
            # If in csv mode
            if(args.csv):
                # Set the value to a key=value string list joined by ;
                hop_dict["hop{}".format(hop["hop"])] = ';'.join(f'{key}={value}' for key, value in hop_obj.items())
            else:
                info_dict["Hops"].append(deepcopy(hop_obj))
    
        # If in csv mode
        if(args.csv):
            # Set the total delay value
            info_dict["General Info"]["total_delay"] = total_delay

            # Keep only the selected keys from the general info value
            info_dict["General Info"] = {key: info_dict["General Info"][key] for key in general_args}

            # Add the hop and general info joined dict to the list
            joined_dict = deepcopy(info_dict["General Info"])
            for k, v in hop_dict.items():
                joined_dict[k] = v
            output_rows.append(joined_dict)
        elif(not args.aggr):
            # Set the total delay value
            info_dict["General Info"]["total_delay"] = general_info_colored("Total Delay","{} seconds".format(total_delay))

            # Keep only the selected keys from the general info value and format it with line break
            info_dict["General Info"] = [str(info_dict["General Info"][key]) for key in general_args]


            # Adjust column sizes relatively to general width
            for hop in info_dict["Hops"]:
                for key in ["from","by"]:
                    hop[key] = "\n".join(textwrap.wrap(str(hop[key]),int(console_width*0.3)))


            # Append the row to the array
            output_rows.append(deepcopy(info_dict))
        else: # If in aggregation mode

            # If no key was created yet then create it
            if info_dict["General Info"]["from"] not in aggr_dict.keys():
                aggr_dict[info_dict["General Info"]["from"]] = {"data":[],"all_emails":[]}

            # Set object for reference
            aggr_obj = aggr_dict[info_dict["General Info"]["from"]]

            # Loop through all hops
            for hop in info_dict["Hops"]:

                # 'found a match' flag
                found = False

                # Search for a data row with the same hop details, if found append the mail filename to the list
                # If not - create a new row
                for obj in aggr_obj["data"]:
                    if(obj["from domain"] == hop["from"] and obj["by domain"]==hop["by"] and obj["serial"]==hop["serial"]):
                        if(not info_dict["General Info"]["file_name"] in obj["mails"]):
                            obj["mails"].append(info_dict["General Info"]["file_name"])
                        found = True
                        break
                if(not found):
                    aggr_obj["data"].append({
                        "serial": hop["serial"],
                        "from domain": hop["from"],
                        "by domain": hop["by"],
                        "mails": [info_dict["General Info"]["file_name"]]
                    })
            # Add the file to the total emails list
            aggr_obj["all_emails"].append(info_dict["General Info"]["file_name"])

    except Exception as e:
        print(e)
        print("Failed formatting the {} file".format(file_name))

# If in csv mode create a file and else print a tabular console output
if(args.csv):
    # Create csv folder if not existent
    csv_folder_path = args.csvFolder
    if(not os.path.exists(csv_folder_path)):
        os.mkdir(csv_folder_path)

    # Create a csv file with the name of the current datetime
    csv_file_path = os.path.join(csv_folder_path,"{}.csv".format(time.strftime("%Y%m%d-%H%M%S")))
    with open(csv_file_path, 'w',encoding="utf-8",newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Set the first row according to the row with the most columns - the one with the most hops
        largest_row = max(output_rows, key=lambda x:len(x))
        writer.writerow(largest_row.keys())
        for dictionary in output_rows:
            writer.writerow(dictionary.values())
    print("Successfully created the {} file".format(csv_file_path))
elif(not args.aggr): # If in console mode

    # Go through all rows
    for dic in output_rows:
        # Print the general info
        print("\n".join(dic["General Info"]))
        table_rows = []
        hop_keys = ""
        # Break the lines of the hops
        for hop in dic["Hops"]:
            table_rows.append(list(hop.values()))
            hop_keys = hop.keys()

        # Print the hops table
        print(tabulate(table_rows,headers=hop_keys,tablefmt="fancy_grid"))
        print();print()
else:
    # Foreach email aggregation
    for key,value in aggr_dict.items():
        if sender_domain:
            if key == sender_domain:
                # Print aggregation info
                print(general_info_colored("Sender Domain", key))
                value["all_emails"] = sorted(value["all_emails"])
                print(general_info_colored("Emails", ";".join(value["all_emails"])))
                # Sort data by hop serial number
                value["data"] = sorted(value["data"], key=lambda d: d['serial']) 
                output_rows = []
                max_values_dict = {}
                bad = []
                # Calculate percentage and document in max values dictionary foreach hop number
                for values in value["data"]:
                    values["perct"] = (len(values["mails"])/len(value["all_emails"]))*100
                    if(values["serial"] not in max_values_dict.keys()):
                        max_values_dict[values["serial"]] = values["perct"]
                    else:
                        max_values_dict[values["serial"]] = max(max_values_dict[values["serial"]],values["perct"])
                # Color hops accordingly to the max percentage
                for values in value["data"]:
                    if(values["perct"] == 100):
                        perct = colored(str(values["perct"])+"%","green")
                    elif(values["perct"] == max_values_dict[values["serial"]]):
                        perct = colored(str(values["perct"])+"% (Majority)","yellow")
                    else:
                        perct = colored(str(values["perct"])+"%","red")
                        bad.extend(values["mails"])
                    # Join the email files names
                    values["mails"] = "\n".join(values["mails"])
                    values["perct"] = perct
                    output_rows.append(list(values.values()))
                # Print the filename that appears the most in the bad values list
                if (len(bad) != 0):
                    print(general_info_colored("Most Anomalous Email: ",max(set(bad), key = bad.count)))
                else:
                    print("no file that appears the most in the bad values list")
                # Print statistics table
                print(tabulate(list(output_rows),headers=["serial","from domain","by domain","emails","perct"],tablefmt="fancy_grid"))
                print();print()
        else:
            # Print aggregation info
            print(general_info_colored("Sender Domain", key))
            value["all_emails"] = sorted(value["all_emails"])
            print(general_info_colored("Emails", ";".join(value["all_emails"])))
            # Sort data by hop serial number
            value["data"] = sorted(value["data"], key=lambda d: d['serial']) 
            output_rows = []
            max_values_dict = {}
            bad = []
            # Calculate percentage and document in max values dictionary foreach hop number
            for values in value["data"]:
                values["perct"] = (len(values["mails"])/len(value["all_emails"]))*100
                if(values["serial"] not in max_values_dict.keys()):
                    max_values_dict[values["serial"]] = values["perct"]
                else:
                    max_values_dict[values["serial"]] = max(max_values_dict[values["serial"]],values["perct"])
            # Color hops accordingly to the max percentage
            for values in value["data"]:
                if(values["perct"] == 100):
                    perct = colored(str(values["perct"])+"%","green")
                elif(values["perct"] == max_values_dict[values["serial"]]):
                    perct = colored(str(values["perct"])+"% (Majority)","yellow")
                else:
                    perct = colored(str(values["perct"])+"%","red")
                    bad.extend(values["mails"])
                # Join the email files names
                values["mails"] = "\n".join(values["mails"])
                values["perct"] = perct
                output_rows.append(list(values.values()))
            # Print the filename that appears the most in the bad values list
            if (len(bad) != 0):
                print(general_info_colored("Most Anomalous Email: ",max(set(bad), key = bad.count)))
            else:
                print("no file that appears the most in the bad values list")
            # Print statistics table
            print(tabulate(list(output_rows),headers=["serial","from domain","by domain","emails","perct"],tablefmt="fancy_grid"))
            print();print()
