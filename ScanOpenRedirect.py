from re import sub, search
from json import loads
from os import getenv
import requests
import argparse

def validaciones(url, parametros_url, redirect_url, payload):
	params = sub(redirect_url, payload, parametros_url)
	r = requests.get(url, params=params, headers={"User-Agent": "Firefox AppSec", "Cookie": cookies})
	try:
		if "pong" in r.text and r.headers['host-header'] == '8441280b0c35cbc1147f8ba998a563a7':
			with open('vulnerable_open_redirect.txt', 'a') as archivo:
				archivo.write(url+'?'+params+"\n")
			print(url+'?'+params+" --> URL VULNERABLE A OPEN REDIRECT")
		if search("pfelilpe.com\\u002Fping", r.text):
			with open('otros_posibles_dom_open_redirect.txt', 'a') as archivo:
				archivo.write(url+'?'+params+" --> REVISAR\n")
			print(url+'?'+params+" --> REVISAR SI ES VULNERABLE")
		else:
			return ""
	except:
		return ""

def scan_open_redirect(lista_urls):
	payloads = ['=https://pfelilpe.com/ping?', '=//pfelilpe.com/ping?', '=pfelilpe.com/ping?','=\/\/pfelilpe.com/ping?', '=https:pfelilpe.com/ping?', 'https://@pfelilpe.com/ping?', 'https://\@pfelilpe.com/ping?']
	for url in lista_urls:
		try:
			parametros_url = url.split('?')[1]
			url = url.split('?')[0]
			redirect_url = search(r'(%253D|%3D|=)http(s|)(%253A|%3A|:)(%252F|%2F|\/)(%252F|%2F|\/)[A-Za-z0-9-]+\.', parametros_url).group(0)
			for payload in payloads:
				validaciones(url, parametros_url, redirect_url, payload)
		except Exception as e:
			pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', help="File with urls", required=True)
    parser.add_argument('-c', '--cookies', help="Cookies for requests. Ej: session_id=test123", required=False)
    args = parser.parse_args()
    file =  args.file
    if args.cookies:
        cookies = args.cookies
    else:
	cookies = ''
    with open(file, 'r') as archivo:
        lista_urls = archivo.read().splitlines()
    scan_open_redirect(lista_urls)
