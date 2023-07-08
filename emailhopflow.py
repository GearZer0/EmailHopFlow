import mailparser
import json
import re
from tabulate import tabulate
import os
from copy import deepcopy
from termcolor import colored
import argparse
import csv
import time
import textwrap
import glob
from itertools import groupby
import sys

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
      
def generate_minimized_csv(mail):
    output_rows = []

    for to_record in mail.to:
        output_rows.append({"message_id": mail.message_id, "recipient": to_record[1]})

    for to_record in mail.cc:
        output_rows.append({"message_id": mail.message_id, "recipient": to_record[1]})
    return output_rows

def create_csv(csv_folder_path,file_prefix,output_rows):
    # Create csv folder if not existent
    if(not os.path.exists(csv_folder_path)):
        os.mkdir(csv_folder_path)
    # Create a csv file with the name of the current datetime
    csv_file_path = os.path.join(csv_folder_path,"{}{}.csv".format(file_prefix,time.strftime("%Y%m%d-%H%M%S")))
    with open(csv_file_path, 'w',encoding="utf-8",newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Set the first row according to the row with the most columns - the one with the most hops
        largest_row = max(output_rows, key=lambda x:len(x.keys()))
        writer.writerow(largest_row.keys())
        
        for dictionary in output_rows:
            writer.writerow(dictionary.values())
    print("Successfully created the {} file".format(csv_file_path))

def insert_auth_result_placeholder(filename):
    with open(filename,"r+") as file:
        fhread = file.readlines()
        findz = "Authentication-Results:"
        
        is_present = False
        for line in fhread:
            if line.startswith(findz):
                is_present = True
                break

        if (not is_present):
            previous_text = ""
            for i in fhread:
                previous_text += i
            file.write("Authentication-Results: INTERNAL_PLACEHOLDER\n" + previous_text)

def aggregate_summary(key,value):
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

def create_hop_obj(hop, aggr_mode):
    hop_obj = {}

    hop_obj["serial"] = hop["hop"]

    # Find the source and destination using a '<fqdn>(0 or more) <ip>' regex
    ip_fqdn_pattern = re.compile("(((?=.{4,253}\.?$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?)\s*)*\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})*)")

    try:
        hop_obj["from"] = ip_fqdn_pattern.findall(hop["from"])[0][0]
    except:
        hop_obj["from"] = ""
    try:
        ip_pattern = re.compile("(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
        hop_obj["from_ip"] = ip_pattern.findall(hop["from"])[0]
    except:
        hop_obj["from_ip"] = ""
    try:
        hop_obj["by"] = ip_fqdn_pattern.findall(hop["by"])[0][0]
    except:
        hop_obj["by"] = ""

    hop_obj["date_utc"] = hop["date_utc"]
    hop_obj["delay"] = hop["delay"]
    try:
        hop_obj["for"] = hop["for"]
    except:
        hop_obj["for"] = ""

    if(aggr_mode):
        for key in ["from","by"]:
            try:
                first_word = hop_obj[key].split(" ")[0]
                hop_obj[key] = re.findall("\w+\.\w+$",first_word)[0]
            except:
                hop_obj[key] = hop_obj[key]
    return hop_obj

def create_parser():
    class MyParser(argparse.ArgumentParser):
        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)
    # Declare argument variables
    parser = MyParser(
                        prog = 'mailflow_tool.py',
                        description = 'A simple cli tool to track multiple email messages - showing general info and hops')
    parser.add_argument('-n','--normal',
                action='store_true',
                default=False,
                help="Parse each email and display its general info and hops table")
    parser.add_argument('-g','--general',
                action='store',
                default="file_name,spf_ip,id,subject,date,from,to,spf,dkim,dmarc,rcv_spf,total_delay",
                help="Comma delimited list of keys to show in each email general info - Ignored if in aggr mode (DEFAULT: file_name,id,subject,date,from,spf,dkim,dmarc,rcv_spf,total_delay)")
    parser.add_argument('-c','--csv',
                action='store_true',
                default=False,
                help="Add this flag if you would like to export data to csv, field filters will be applied - Ignored if in aggr mode")
    parser.add_argument('-mc','--minCsv',
                action='store_true',
                default=False,
                help="Add this flag if you would like to export data to minimized csv - Ignored if in aggr mode")
    parser.add_argument('-sh','--selecthop',
                action='store',
                default=0,
                help="Add this flag if you would like to get info about a specific hop number, use -1 to access the last hop - Ignored if in aggr mode")
    parser.add_argument('-fi','--firstip',
                action='store_true',
                default=False,
                help="Add this flag if you would like to get info about the first hop that has ip address in it - Ignored if in aggr mode")
    parser.add_argument('-a','--aggr',
                action='store_true',
                default=False,
                help="Add this flag if you would like to aggregate email by root domains")
    parser.add_argument('-s','--select',
                action='store',
                default="",
                help="Add this flag if you would like to group hops by a field (currently working only in -fi and-or -sh modes)")
    parser.add_argument('-sd','--senderdomain',
                action='store',
                default="",
                help="Add this flag if you would like to aggregate for one domain only")
    parser.add_argument('-r','--recursive',
                action='store_true',
                default=False,
                help="Add this flag if you would like to search recursively in the emailFolder")
    parser.add_argument('-ef','--emailFolder',
                action='store',
                default=os.path.join(os.path.dirname(__file__),"emails"),
                help="The path to the emails folder, will fail if not exists (DEFAULT: {})".format(os.path.join(os.path.dirname(__file__),"emails")))
    parser.add_argument('-cf','--csvFolder',
                action='store',
                default=os.path.join(os.path.dirname(__file__),"csv"),
                help="The path to where output the csv files, will create if not existent and csv mode selected (DEFAULT: {})".format(os.path.join(os.path.dirname(__file__),"emails")))
    parser.add_argument('-mcf','--minCsvFolder',
                action='store',
                default=os.path.join(os.path.dirname(__file__),"minimized_csv"),
                help="The path to where output the csv files, will create if not existent and csv mode selected (DEFAULT: {})".format(os.path.join(os.path.dirname(__file__),"emails")))
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return parser

def generate_general_info(mail, aggr_mode, csv_mode, short_filename):
        general_info_obj = {}

        # Set default values for common keys
        general_info_obj["file_name"] = short_filename
        general_info_obj["from"] = mail._from[0][1].split("@")[1]

        if(not aggr_mode): # If not in aggregate mode (csv/normal)
            # The parameters for both csv and normal mode are very simillar - just a question of coloring and ; or line break
            join_char = ";" if csv_mode else "\n"
            
            spf_ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            try:
                spf_ip = spf_ip_pattern.search(mail.received_spf[0])[0]
            except:
                spf_ip = 'No_SPF_Field'

            general_info_obj["spf_ip"] = parse_accordingly("SPF-IP",spf_ip)

            general_info_obj["id"] = parse_accordingly("Message-ID",mail.message_id)
            general_info_obj["subject"] = parse_accordingly("Subject",mail.subject)
            general_info_obj["date"] = parse_accordingly("Date",mail.date)

            # The to property is in pairs (name - address), join the pairs and append to one list
            general_info_obj["to"] = parse_accordingly("To",join_char.join(list(map(join_tuple_string, mail.to))))
            
            # The from property is in pairs (name - address), join the pairs and append to one list
            general_info_obj["from"] = parse_accordingly("From",join_char.join(list(map(join_tuple_string, mail.from_))))
            

            # Get the authentication header content
            authentication = json.loads(mail.headers_json)["Authentication-Results"]
            # Find for each protocol the status from the auth header
            general_info_obj["spf"] = parse_accordingly("SPF",";".join(re.findall("(?<=spf=).*",authentication)))
            general_info_obj["dkim"] = parse_accordingly("DKIM",";".join(re.findall("(?<=dkim=).*",authentication)))
            general_info_obj["dmarc"] = parse_accordingly("DMARC",";".join(re.findall("(?<=dmarc=).*",authentication)))
            
            # Parse the received-spf header from the raw email content using regex
            spf_pattern = re.compile("(Received-SPF:(?s:.*?)(?=\\nReceived:))", re.VERBOSE | re.MULTILINE)
            matches = spf_pattern.findall(read_stream)

            # Remove line breakers 
            matches = [string.replace("\n","") for string in matches ]
            
            # If not in csv mode we should color the Received-SPF: words
            replace_to = "Received-SPF:" if args.csv else colored("Received-SPF:","green")
            general_info_obj["rcv_spf"] = (join_char.join(matches)).replace("Received-SPF:",replace_to)
        return general_info_obj
        
def print_console(output_rows):
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

def print_combined_table(output_rows):
    table_rows = []
    hop_keys = ""
    # Go through all rows
    for dic in output_rows:
        # Break the lines of the hops
        for hop in dic["Hops"]:
            table_rows.append(list(hop.values()))
            hop_keys = hop.keys()

    # Print the hops table
    print(tabulate(table_rows,headers=hop_keys,tablefmt="fancy_grid"))

def print_aggregate(aggr_dict,sender_domain):
    # Foreach email aggregation
    for key,value in aggr_dict.items():
        if not sender_domain or key == sender_domain:
            aggregate_summary(key,value)

def prepare_hops_for_console(hops_array):
    # The width of the console, will be used for relative column printing in console mode
    console_width = os.get_terminal_size().columns

    # Adjust column sizes relatively to general width
    for hop in hops_array:
        relative_part = 1/len(hop.keys())
        for key in hop.keys():
            hop[key] = "\n".join(textwrap.wrap(str(hop[key]),int(console_width*relative_part)))
    return hops_array
    
def prepare_info_dict_for_console(info_dict, general_args):

    # Keep only the selected keys from the general info value and format it with line break
    info_dict["General Info"] = [str(info_dict["General Info"][key]) for key in general_args]

    # Adjust column sizes relatively to general width
    info_dict["Hops"] = prepare_hops_for_console(info_dict["Hops"])
    
    return info_dict

def prepare_info_dict_for_select_mode(info_dict,filename):
    info_dict["General Info"] = {}
    for hop in info_dict["Hops"]:
        hop["filename"] = filename
    return info_dict

def print_select(output_rows, select_field):

    new_output_rows = []
    # define a function for key
    def key_func(k):
        return k['Hops'][0][select_field]
    
    # sort INFO data by 'company' key.
    output_rows = sorted(output_rows, key=key_func)
    
    for key, value in groupby(output_rows, key_func):
        hops_temp = []
        for obj in list(value):
            hops_temp.extend(obj["Hops"])
        new_output_rows.append({"General Info": {general_info_colored(select_field, key)}, "Hops":prepare_hops_for_console(hops_temp) })

    print_console(new_output_rows)


parser = create_parser()
# Parse arguments and perform validity checks

args = parser.parse_args()

# Split the field lists by comma
#hop_args = args.hop.split(",")
general_args = args.general.split(",")

# set aggregate filter domain
sender_domain = args.senderdomain

if(args.aggr): args.csv = False

# Check if emails path exists
emails_path = args.emailFolder
if(not os.path.exists(emails_path)):
    raise ValueError("No {} directory".format(emails_path))

# The table rows variable - represents console table or csv file rows
output_rows = []
min_output_rows = []
aggr_dict = {}

# Loop through all the email files in the path
for file_name in glob.glob(os.path.join(emails_path,"**"),recursive=args.recursive):

    # If the path specified is not a file then skip this loop run
    if(not os.path.isfile(file_name)):
        continue
    short_filename = os.path.basename(file_name)
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

        if (args.minCsv):
            min_output_rows.extend(generate_minimized_csv(mail))

        # The mail info dictionary 
        info_dict = {}

        # The general info property (non hop related data)
        info_dict["General Info"] = generate_general_info(mail,args.aggr,args.csv,short_filename)

        # The total delay variable - will be the sum of all hop delays
        total_delay = 0.0

        # Initialize the hop info properties, relevant for console mode
        info_dict["Hops"] = []

        # Initialize the hop dictionary, relevant for csv mode
        hop_dict = {}

        # Loop through all hops
        for hop in json.loads(mail.received_json):
            # Set a dictionary key for each hop: hop1,hop2,...
            hop_name = "hop{}".format(hop["hop"])
            hop_obj = create_hop_obj(hop,args.aggr)

            total_delay += float(hop_obj["delay"])

            # If in csv mode
            if(args.csv):
                # Set the value to a key=value string list joined by ;
                hop_dict[hop_name] = ';'.join(f'{key}={value}' for key, value in hop_obj.items())
            else:
                info_dict["Hops"].append(deepcopy(hop_obj))
        if(not args.aggr):
            # Set the total delay value
            info_dict["General Info"]["total_delay"] = general_info_colored("Total Delay","{} seconds".format(total_delay))

            if(args.csv):
                for to_record in mail.to:
                    info_dict["General Info"]["to"] = to_record
                    info_dict["General Info"] = {key: info_dict["General Info"][key] for key in general_args}
                    # Add the hop and general info joined dict to the list
                    joined_dict = deepcopy(info_dict["General Info"])
                    for k, v in hop_dict.items():
                        joined_dict[k] = v
                    output_rows.append(joined_dict)
                    
                for to_record in mail.cc:
                    info_dict["General Info"]["to"] = to_record
                    info_dict["General Info"] = {key: info_dict["General Info"][key] for key in general_args}
                    # Add the hop and general info joined dict to the list
                    joined_dict = deepcopy(info_dict["General Info"])
                    for k, v in hop_dict.items():
                        joined_dict[k] = v
                    output_rows.append(joined_dict)
                
            elif(args.selecthop != 0 | args.firstip):
                    info_dict["General Info"] = {}

                    sh_selected_hop = {}
                    fi_selected_hop = {}

                    if(args.selecthop != 0):
                        try:
                            hop_num = int(args.selecthop)
                            if(hop_num > 0):
                                sh_selected_hop = deepcopy(info_dict["Hops"][hop_num -1])
                            else:
                                sh_selected_hop = deepcopy(info_dict["Hops"][hop_num])
                        except:
                            pass

                    if(args.firstip):
                        for hop in info_dict["Hops"]:
                            if(hop["from_ip"] != ""):
                                fi_selected_hop = deepcopy(hop)
                                break

                    for selected_hop in [fi_selected_hop,sh_selected_hop]:
                        if(selected_hop != {}):
                            constructed_hop = {}

                            constructed_hop["filename"] = short_filename
                            constructed_hop["hop_num"] = selected_hop["serial"]

                            fqdn_pattern = re.compile("((?=.{4,253}\.?$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?))")
                            #count = 1
                            #for finding in fqdn_pattern.findall(selected_hop["from"]):
                            #    constructed_hop["from"+str(count)] = finding[1]
                            #    count+=1
                            
                            try:
                                constructed_hop["from1"] = fqdn_pattern.findall(selected_hop["from"])[0][1]
                            except:
                                constructed_hop["from1"] = ""

                            try:
                                constructed_hop["from2"] = fqdn_pattern.findall(selected_hop["from"])[1][1]
                            except:
                                constructed_hop["from2"] = ""
                            
                            constructed_hop["by"] = selected_hop["by"]
                            constructed_hop["for"] = selected_hop["for"]

                            constructed_hop["from_ip"] = selected_hop["from_ip"]

                            info_dict["Hops"] = [deepcopy(constructed_hop)]

                            if(not args.select):
                                output_rows.append(deepcopy(prepare_info_dict_for_console(info_dict, [])))
                            else:
                                output_rows.append(deepcopy(prepare_info_dict_for_select_mode(info_dict,short_filename)))
            else:
                # Append the row to the array
                if(not args.select):
                    output_rows.append(deepcopy(prepare_info_dict_for_console(info_dict, general_args)))
                else:
                    output_rows.append(deepcopy(prepare_info_dict_for_select_mode(info_dict,short_filename)))
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


if(args.minCsv):
    create_csv(args.minCsvFolder,"min-",min_output_rows)
if(args.csv):
    create_csv(args.csvFolder,"",output_rows)
elif(args.select):
    print_select(output_rows,args.select)
elif(args.selecthop != 0 | args.firstip):
    print_combined_table(output_rows)
elif(not args.aggr): # If in console mode
    print_console(output_rows)
else:
    print_aggregate(aggr_dict,sender_domain)
