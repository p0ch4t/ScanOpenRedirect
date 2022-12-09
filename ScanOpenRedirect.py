from re import sub, search
from json import loads
from os import getenv
import requests
import argparse

def validaciones(url, parametros_url, redirect_url, payload):
	params = sub(redirect_url, payload, parametros_url)
	r = requests.get(url, params=params)
	try:
		if "pong" in r.text and r.headers['host-header'] == '8441280b0c35cbc1147f8ba998a563a7':
			return url+'?'+params
		if "https:\u002F\u002Fpfelilpe.com\u002Fping" in r.text:
			with open('otros_posibles_dom_open_redirect.txt'):
				print(url+'?'+params+" --> REVISAR")
		else:
			return ""
	except:
		return ""

def scan_open_redirect(lista_urls):
	payloads = ['=https://pfelilpe.com/ping?', '=//pfelilpe.com/ping?', 
'=pfelilpe.com/ping','=\/\/pfelilpe.com/ping?', '=https:pfelilpe.com/ping?']
	for url in lista_urls:
		try:
			parametros_url = url.split('?')[1]
			url = url.split('?')[0]
			redirect_url = search(r'(%253D|%3D|=)http(s|)(%253A|%3A|:)(%252F|%2F|\/)(%252F|%2F|\/)[A-Za-z0-9-]+\.', parametros_url).group(0)
			for payload in payloads:
				url_maliciosa = validaciones(url, parametros_url, redirect_url, payload)
				print(url_maliciosa)
		except Exception as e:
			pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', help="File with urls", required=True)
    args = parser.parse_args()
    file =  args.file
    with open(file, 'r') as archivo:
        lista_urls = archivo.read().splitlines()
    scan_open_redirect(lista_urls)
