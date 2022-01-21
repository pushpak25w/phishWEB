from urllib.parse import urlparse
import requests
import string
import ipaddress
import tldextract
import whois
import datetime
from bs4 import BeautifulSoup as bs
from pyfiglet import Figlet,figlet_format
from termcolor import colored
from rich.console import Console
console = Console()
def log(string, color, font, figlet):
    if colored:
        if not figlet:
            print(colored(string, color))
        else:
            print(colored(figlet_format(string, font=font), color))
    else:
        print(string)

#Features:

# 1 'having_IP_Address'
# 2 'URL_Length'
# 3 'Shortining_Service'
# 4 'having_At_Symbol'
# 5 'double_slash_redirecting'
# 6 'Prefix_Suffix'
# 7 'having_Sub_Domain'
# 8 'SSLfinal_State'
# 9 'Domain_registeration_length',
# 10 'Favicon'
# 11 'HTTPS_token'
# 12 'Request_URL'
# 13 'URL_of_Anchor',
# 14 'Links_in_tags'
# 15 'SFH'
# 16 'Submitting_to_email'
# 17 'Redirect'
# 18 'on_mouseover'
# 19 'RightClick'
# 20 'Iframe',
# 21 'age_of_domain'
# 22 'DNSRecord'
# 23 'web_traffic'
# 24 'Page_Rank',
# 25 'Statistical_report'

def f1_having_IP_Address(domain):
    #1. checking hex digits
    domainhex = domain
    domainhex = domainhex.replace(".", "")
    domainhex = domainhex.replace("0x", "0")
    count = 0
    for dig in domainhex:
        if dig in string.hexdigits:
            count+=1

    if(count>=len(domainhex)):
        return -1

    #2. checking direct IP address
    try:
        ipaddress.ip_address(domain)
        return -1
    except:
        return 1

def f2_URL_Length(url):
    if len(url)>=54:
        if len(url)>75:
            return -1
        return 0
    return 1

def f3_Shortening_Service(url):
    services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'rebrand.ly', 't.co', 'youtu.be', 'ow.ly', 'w.wiki', 'ff.me', 'tiny.cc', 'ur14.eu', 'twurl.nl', 'snipurl.com', 'short.to' ]
    
    ind = url.find("https://")
    newurl = url
    if(ind!=-1):
        newurl = url[(ind+8):]

    index = newurl.find("/")
    if(index==-1):
        return 1
    service = newurl[:index]

    if service in services:
        return -1
    else:
        return 1

def f4_having_At_Symbol(url):
    if "@" in url:
        return -1
    return 1

def f5_double_slash_redirecting(url):
    pos = url.rfind("//")
    if (pos > 5):
        if (pos > 6):
            return -1
        else:
             return 1
    else:
        return 1

def f6_Prefix_Suffix(domain):
    if "-" in domain:
        return -1
    return 1

def f7_having_sub_domain(domain):
    subdom = domain[3: domain.rfind(".")]
    count = 0
    for pt in subdom:
        if pt==".":
            count+=1
    
    if count>1:
        if count>2:
            return -1
        else:
            return 0
    else:
         return 1

def f9_Domain_registration_length(whois_info):
    try:
        exp_date = whois_info.expiration_date
        today = datetime.datetime.now()
        length = exp_date[0] - today
        if length>datetime.timedelta(days=365):
            return 1
        else:
            return -1
    except:
        return -1

def f10_Favicon(domain):
    href = []
    for icon in soup.find_all("link", rel="shortcut icon"):
        href.append(icon.get('href'))

    for h in href:
        if(h=="favicon.ico"):
            return 1
        else:
            dom = urlparse(h).netloc
            if (dom!=domain and dom!='' and dom!=b''):
                return -1
    return 1



def f11_HTTPS_token(domain):
    if ("https" in domain) or ("http" in domain):
        return -1
    return 1

def checkperc(oth, cnt):
    perc = 0
    if(cnt!=0):
        perc = (oth*100)/cnt
    return perc

def f12_Request_URL(domain):
    percimg = f121_findsrcdomain('img', domain)
    percvid = f121_findsrcdomain('video', domain)
    percsound = f121_findsrcdomain('embed', domain)

    perc = percimg + percvid + percsound

    if perc>=21:
        if perc>=61:
            return -1
        else:
            return 0
    else:
        return 1

def f121_findsrcdomain(tag, domain):

    srcs = []
    invalidhref = 0
    count = 0

    for t in soup.find_all(tag):
        srcs.append(t.get('src'))

    for src in srcs:
        dom = urlparse(src).netloc
        if (dom!=domain and dom!='' and dom!=b''):
            invalidhref+=1 
    count=len(srcs)
    perc = checkperc(invalidhref, count)
    return (perc)

def f13_URl_of_Anchor(domain):
    
    href = []
    count = 0
    invalidhref = 0

    for a in soup.find_all('a'):
        href.append(a.get('href'))
    nullweb = ['#', '#content', '#skip', 'JavaScript ::void(0)']

    for h in href:
        if h in nullweb:
            invalidhref+=1
        else:
            dom = urlparse(h).netloc
            if (dom!=domain and dom!='' and dom!=b''):
                invalidhref+=1 
    count=len(href)
    perc = checkperc(invalidhref, count)

    if perc>=31:
        if perc>67:
            return -1
        else:
            return 0
    return 1

def f14_Links_in_tags(domain):
    othlink, cntlink = f141_find_domain('link', domain)
    othscript, cntscript = f141_find_domain('script', domain)
    othmeta, cntmeta = f141_find_domain('meta', domain)
    perclink = checkperc(othlink, cntlink)
    percscript = checkperc(othscript, cntscript)
    percmeta = checkperc(othmeta, cntmeta)
    
    perc = perclink + percmeta + percscript
    
    if perc>=17:
        if perc>81:
            return -1
        else:
            return 0
    return 1

def f141_find_domain(tag, domain):
    href = []
    link_other_domain = 0
    count = 0

    for t in soup.find_all(tag):
        href.append(t.get('href'))

    for h in href:
        dom = urlparse(h).netloc
        if (dom!=domain and dom!='' and dom!=b''):
            link_other_domain+=1
        count+=1

    return (link_other_domain, count)

def f16_Submitting_to_email():
    form = str(soup.form)
    email = form.find("mail()")
    if email == -1:
        email = form.find("mailto:")
    if email == -1:
        return 1
    return -1

def f17_Redirect(url):
    response=requests.get(url)
    if len(response.history) <=1:
        return 1
    if len(response.history) >=4:
        return -1
    return 0

def f18_on_mouseover():
    if str(soup).lower().find('onmouseover="window.status')!=-1:
        return -1
    return 1

def f19_RightClick():
    if str(soup).lower().find("event.button==2")!=-1:
        return -1
    return 1

def f20_Iframe(result):
    if result=="":
        return -1
    if str(soup.iframe).lower().find("frameborder") == -1:
        return 1
    return -1

def f21_age_of_domain(whois_info):
    try:
        cre_date = whois_info.creation_date
        exp_date = whois_info.expiration_date
        age = exp_date-cre_date
        #print(age,datetime.timedelta(days=180))
        if age>=datetime.timedelta(days=180):
            return 1
        else:
            return -1
    except:
        return -1

def f22_DNSRecord(whois_info):
    if whois_info==None or ['domain_name'][0]=="nothing":
        return -1
    else:
        return 1

def f23_web_traffic(url):
    try:
        extract_res = tldextract.extract(url)
        url_ref = extract_res.domain + "." + extract_res.suffix
        html_content = requests.get("https://www.alexa.com/siteinfo/" + url_ref).text
        soup = bs(html_content, "lxml")
        value = str(soup.find('div', {'class': "rankmini-rank"}))[42:].split("\n")[0].replace(",", "")
    except:
        return -1
        
    if not value.isdigit():
        return -1

    value = int(value)
    if value < 100000:
        return 1
    return 0


#driver function

features = []
features_model=[]
soup=''
abc=[]
def extract(url):
    global features
    global abc
    for i in range(25):
        features.append('-')

    features[2] = f3_Shortening_Service(url)
    console.print(f"[01] checked if Shortening_Service is used...")

    if(features[2]==-1):
        ind = url.find("https://")       #remove https if present in tinyurl
        if(ind!=-1):
            url = url[(ind+8):]
        url = requests.head("http://"+url).headers['location']

    domain = urlparse(url).netloc
    try:
        #print(domain)
        whois_info=whois.whois(domain)
    except:
        whois_info={'domain_name':["nothing"]}
    try:
        result = requests.get(url)
        src = result.content
        global soup
        soup = bs(src, 'lxml')
        flag = 0
    except:
        return "Website doesn't exist!"

    if flag==0:
        features[16]=f17_Redirect(url)
        console.print(f"[02] checked if redirecting to other websites...")
        #domain based features
        features[0] = f1_having_IP_Address(domain)
        console.print(f"[03] checked if url has IP address...")
        features[5] = f6_Prefix_Suffix(domain)
        features[6] = f7_having_sub_domain(domain)
        console.print(f"[04] checked subdomains...")
        features[8] = f9_Domain_registration_length(whois_info)
        console.print(f"[05] checked domain registration details...")
        features[10] = f11_HTTPS_token(domain)
        console.print(f"[06] checked https token...")
        features[11] = f12_Request_URL(domain)
        console.print(f"[07] checked if we can make requests...")
        features[12] = f13_URl_of_Anchor(domain)
        console.print(f"[08] calculated anchor tags percentage...")
        features[13] = f14_Links_in_tags(domain)
        console.print(f"[09] calculated link in tags percentage...")
        features[20] = f21_age_of_domain(whois_info)
        console.print(f"[10] checked age of domain...")

        #url based features
        features[1] = f2_URL_Length(url)
        console.print(f"[11] checked url length...")
        features[3] = f4_having_At_Symbol(url)
        console.print(f"[12] checked at_symbol...")
        features[4] = f5_double_slash_redirecting(url)
        console.print(f"[13] checked double slash redirecting...")
        features[22] = f23_web_traffic(url)
        console.print(f"[14] checked web traffic...")
        #other
        features[15] = f16_Submitting_to_email()
        console.print(f"[15] checked if details are submitted to mail...")
        features[17] = f18_on_mouseover()
        console.print(f"[16] checked if mouseover...")
        features[18] = f19_RightClick()
        console.print(f"[17] checked if source code is available...")
        features[19] = f20_Iframe(result)
        console.print(f"[18] checked if used Iframe...")
        features[7]=features[21] = f22_DNSRecord(whois_info)
        console.print(f"[19] fetched DNS record...")
        features[9] = f10_Favicon(domain)
        console.print(f"[20] favicon checked...")

    count = 0
    global features_model
    global warnings
    warnings = []

    for i in range(25):
        if features[i]==0 or features[i]==-1 or features[i]==1:
            if features[i]==-1:
                if (i==4):
                    warnings.append("[*] You'll be redirected to another website!")
                elif(i==15):
                    warnings.append("[*] Your personal details will be misused!")
                elif(i==18):
                    warnings.append("[*] This website hides their source code!")
                elif(i==19):
                    warnings.append("[*] Additional webpage is being hidden into the one that is currently shown!")
                elif(i==21):
                    warnings.append("[*] Website is not recognized by a trusted authority!")
                elif(i==22):
                    warnings.append("[*] This website has a very low web traffic!")

            #print("f", i+1, " = ", features[i])
            features_model.append(features[i])
    return(warnings)

def encoding(data):
    mapper={1:1,0:0,-1:2}
    for i in range(len(data)):
        data[i]=mapper[data[i]]
    return data

import numpy as np
import pickle

def phishing(url):
    global features_model
    global features
    features.clear()
    features_model.clear()
    with console.status("[bold green]extracting features...") as status:
        warnings = extract(url)
    if warnings=="Website doesn't exist!":
        return (404,"")
    features_model=encoding(features_model)
    array=np.array(features_model)
    array=array.reshape(1,-1)
    ans=model.predict(array)
    return (ans, warnings)

def load_files():
    global model
    model=pickle.load(open('./RF','rb'))

load_files()
#url list
#https://tinyurl.com/4jtbxwtr
#https://amazon-co-jp.youtian8332.vip/ - phish
#https://olx.pl.item-pay.site -phish
