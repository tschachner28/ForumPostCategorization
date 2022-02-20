import urllib.error

import docker
from stackapi import StackAPI
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen
import re
import spacy # Also run "python -m spacy download en_core_web_lg"
from spacy import displacy
import csv
import requests

NER = spacy.load("en_core_web_sm")
client = docker.from_env()
posts_dicts = [] # list of dictionaries, each of which contains keys for link, category, and application/image
linux_caps = ['audit_control', 'audit_read', 'audit_write', 'block_suspend', 'bpf', 'checkpoint_restore', 'chown',
              'dac_override', 'dac_read_search', 'fowner', 'fsetid', 'ipc_lock', 'ipc_owner', 'kill', 'lease',
              'linux_immutable', 'mac_admin', 'mac_override', 'mknod', 'net_admin', 'net_bind_service', 'net_broadcast',
              'net_raw', 'perfmon', 'setgid', 'setfcap', 'setpcap', 'setuid', 'sys_admin', 'sys_boot', 'sys_chroot',
              'sys_module', 'sys_nice', 'sys_pacct', 'sys_ptrace', 'sys_rawio', 'sys_resource', 'sys_time',
              'sys_tty_config', 'syslog', 'wake_alarm'] # list of all Linux capabilities

# Input: forum post question or answer
# Output: list of applications mentioned in the input
# Checks for mentions of docker applications in the post's questions and answers
def checkForApps(text):
    # Extract named entities and search them using Docker API to see if they are images
    apps = []
    ner_obj = NER(text.getText())
    named_entities = [word.text for word in ner_obj.ents]
    print(named_entities)
    for entity in named_entities: # Check if entity found in first 3 results
        if entity.find('/') != -1 or entity.find('\\') != -1 or entity.find('.') != -1 or entity.isdigit(): # omit these cases because they make the api crash or return inaccurate results
            continue
        entity = entity.lower()
        applications_results = None
        try:
            applications_results = client.api.search(entity)
        except requests.exceptions.HTTPError:
            continue
        print(applications_results)
        application_found = len(applications_results) > 0 and applications_results[0]['is_official'] == True and\
                            (len(entity) <= len(applications_results[0]['name']) and applications_results[0]['name'][-1-len(entity)+1:].lower() == entity)
        if len(applications_results) > 1:
            application_found = application_found or (applications_results[1]['is_official'] == True and len(entity) <= len(applications_results[1]['name']) and applications_results[1]['name'][-1-len(entity)+1:].lower() == entity)
        if len(applications_results) > 2:
            application_found = application_found or (applications_results[2]['is_official'] == True and len(entity) <= len(applications_results[2]['name']) and applications_results[2]['name'][-1-len(entity)+1:].lower() == entity)
        if application_found:
            apps.append(entity)
    return apps

# Checks for mentions of specific capabilities in the post's question and answers
# Input: text (string)
# output: caps
def checkForCaps(text):
    caps = [] # list of capabilities mentioned in the post
    text = text.getText().lower()
    cap_indices = [_.start() for _ in re.finditer('cap_', text)]  # Check for occurrences of 'cap_' (e.g. CAP_NET_ADMIN)
    cap_add_indices = [_.start() for _ in re.finditer('--cap-add=', text)] # Check for occurrences of --cap-add (e.g. --cap-add=NET_ADMIN)
    cap_occurrences = [i + 4 for i in cap_indices] + [i + 10 for i in cap_add_indices] # start indices of all mentions of capabilities
    for i in cap_occurrences:
        potential_end_inds = [text[i:].find(' '), text[i:].find('\n'), text[i:].find('='), text[i:].find('+'), text[i:].find(')'), text[i:].find(','), text[i:].find('.')]
        potential_end_inds = [ind for ind in potential_end_inds if ind >= 0]
        potential_end_inds = [ind+i for ind in potential_end_inds]
        end_ind = min(potential_end_inds)
        cap_found = text[i:end_ind]
        caps.append(cap_found)
    caps = list(set(caps)) # remove duplicates
    return caps

# Search for posts tagged linux-capabilities
SITE = StackAPI('stackoverflow')
questions = SITE.fetch('questions', tagged='linux-capabilities', sort='votes')
more_questions = SITE.fetch('questions', tagged='docker', sort='votes', todate=1644624000)
all_question_items = questions['items'] + more_questions['items']
#questions += SITE.fetch('questions', tagged='docker', sort='votes')
#print(questions)
#print(len(questions))
count=0
for question in all_question_items:
    print(count)
    count += 1
    url = question['link']
    req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    page = None
    try:
        page = urlopen(req).read()
    except urllib.error.URLError:
        continue
    soup = BeautifulSoup(page, 'html.parser')
    questions_and_answers = soup.find_all("div", {"class": "s-prose js-post-body"})
    post_apps = []
    post_caps = []
    # Find apps mentioned
    for question_or_answer in questions_and_answers:
        apps = checkForApps(question_or_answer)
        post_apps += apps
    post_apps = list(set(post_apps))
    # Find capability categories
    if len(post_apps) == 0:
        for question_or_answer in questions_and_answers:
            caps = checkForCaps(question_or_answer)
            post_caps += caps
    post_caps = list(set(post_caps))
    post_caps = [cap for cap in post_caps if cap in linux_caps]

    # Add post's dictionary to post_dicts
    post_dict = {'Link': url, 'Category': None, 'Application/Capability': None}
    if len(post_apps) > 0:
        post_dict['Category'] = 'Application'
        post_dict['Application/Capability'] = post_apps
    elif len(post_caps) > 0:
        post_dict['Category'] = 'Capability'
        post_dict['Application/Capability'] = post_caps
    else:
        post_dict['Category'] = 'General'
    posts_dicts.append(post_dict)

# Write post categorizations to output file
with open('PostCategorizations.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=list(posts_dicts[0].keys()))
    writer.writeheader()
    writer.writerows(posts_dicts)

