import dns.name
import dns.message
import dns.query
from dns.rcode import Rcode
import time
import datetime

## asking for domain name
domain_name = input("Enter a domain to resolve: ")

root_server_ips = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                   '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129',
                   '199.7.83.42', '202.12.27.33']
print()
print("QUESTION SECTION:")
print(domain_name + " IN A")
print()

## tries to resolve the ip address for given domain input
def my_dig(input, ip_address):
    query = dns.message.make_query(input, 'A')
    try:
        response = dns.query.udp(query, ip_address, timeout=5)
    except:
        ## if there is some error getting response, return empty string
        return ""

    ## if there is an error, then return empty string
    if response.rcode() != Rcode.NOERROR:
        return ""

    ## if there is some type of answer, go inside it
    if len(response.answer) > 0:
        answer = response.answer[0]
        string_answer = str(answer)
        ## print(string_answer)
        if string_answer.find("CNAME") != -1:  ## it is there, so must return false
            string_answer_split = string_answer.split(" ")
            new_input = string_answer_split[-1]
            return main_function(new_input)
        else:
            return string_answer
    else:
        ## if there is nothing in additional, go inside authority
        if len(response.additional) == 0:
            if (len(response.authority) == 0):
                return ""

            answer = response.authority[0]
            string_answer = str(answer)
            string_answer = string_answer.split("\n")[-1]

            new_domain = string_answer.split(" ")[-1]
            ## get new ip address for the new domain name
            new_ip = str(main_function(new_domain))
            new_ip2 = new_ip.split(" ")[-1]
            ## call mydig again
            return my_dig(input, new_ip2)
        else:
            ## here, you have something in additionals
            additional_name_servers = response.additional

            for auth in additional_name_servers:
                ip_address = str(auth[0])
                if ip_address.find(":") == -1:
                    return my_dig(input, ip_address)
            return ""

## call this function whenever you are in root, run through all of them
def main_function(input):
    for ip_address in root_server_ips:
        result = my_dig(input, ip_address)

        ## if the result is valid, length of it should be > 0
        if len(result) != 0:
            return result
    return ""

start = time.time()

result = main_function(domain_name)
## print(result)
end = time.time()

if result == "":
    print("unable to resolve or connect to " + str(domain_name))
else:
    print("ANSWER SECTION:")
    result_split = result.split(" ")[0:5]
    result_split[0] = domain_name

    if (result_split[-1].find("\n")):
        word = ""
        for i in range(len(result_split[-1])):
            letter = result_split[-1][i]
            if letter == "\n":
                result_split[-1] = word
                break
            else:
                word += letter

    result = " ".join(result_split)
    print(result)

print()
total_time = round((end-start)*1000)
print("Query time: " + str(total_time) + " msec")

today = datetime.datetime.now()
print("WHEN: " + str(today) + " EST 2023")
