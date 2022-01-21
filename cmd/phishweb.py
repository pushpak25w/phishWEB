import click
import requests
from features import phishing,console
from pyfiglet import Figlet,figlet_format
from termcolor import colored
@click.command()
@click.option('--url', default='', help='url of website')

def cli(url):
    log("PhishWEB","red","big",True)
    log("Welcome to PhishWEB","blue","slant",False)
    if len(url)==0:
        console.print("[*] enter url: ", style="green",end="")
        #log(": ","green","slant",False)
        url=input()
    with console.status("[bold green]checking if url is reachable...") as status:
        try:
            result = requests.get(url)
        except:
            log("url undreachable :(","yellow","slant",False)
            return
    if result.status_code!=200:
        log("Invalid url.","yellow","slant",False)
        return
    output = ""
    warnings = []
    if(url=="" or url.count('.')==0):
        print("enter valid url")
    val, warnings = phishing(url)
    val = int(val)
    if len(warnings)>0:
        for i in warnings:
            log(i,"yellow","slant",False)
    if val==1:
        console.print("[*] Appears to be a Legitimate website.", style="bold green")
    elif val==0:
        console.print("[*] Appears to be a Suspicious website.", style="bold yellow")
    elif val==404:
        log("[*] Invalid url.","yellow","slant",False)
    else:
        console.print("[*] Appears to be a Phishing website.", style="bold red")


def log(string, color, font, figlet):
    if colored:
        if not figlet:
            print(colored(string, color))
        else:
            print(colored(figlet_format(string, font=font), color))
    else:
        print(string)

if __name__ == '__main__':
    cli()
