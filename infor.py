#coding: latin-1
import requests,json,pathlib,os.path,xmltodict

CheckmarxUrl = "http://cx.kdop.net"
scanid = '1012943'
user = 'admin'
pwd =  '123'
path = r'C:\Users\Rafaela\Desktop\cxresults.json'

def getDescription(scanId, pathId):
	urlDescrip = "https://cxprivatecloud.checkmarx.net/cxrestapi/sast/scans/" + scanId + "/results/" + pathId + "/shortDescription"
	headersDescrip = {'Authorization': gerarCxToken()}
	responseDescrip = requests.request("GET", urlDescrip, headers=headersDescrip)
	
	if responseDescrip.status_code == requests.codes['ok']:
		json_data = json.loads(responseDescrip.text)
		description = json_data['shortDescription']
		return description
	else:
		print("Erro ao obter description : " + responseToken.text)
		exit(1)

def gerarCxToken():
	urlToken = CheckmarxUrl + "/cxrestapi/auth/identity/connect/token"
	username = user
	password = pwd
	scope = "access_control_api%20sast_api"
	clientId = "resource_owner_sast_client"
	payload = 'username=' + username +'&password=' + password + '&grant_type=password&scope=' + scope + '&client_id=' + clientId +'&client_secret=014DF517-39D1-4453-B7B3-9930C563627C'
	headersToken = {'Content-Type': 'application/x-www-form-urlencoded'}
	responseToken = requests.request("POST", urlToken, headers=headersToken, data = payload)

	if responseToken.status_code == requests.codes['ok']:
		json_data = json.loads(responseToken.text)
		tokenCx = "Bearer " + json_data['access_token']
		return tokenCx
	else:
		print("Erro ao gerar token para o Checkmarx : " + responseToken.text)
		exit(1)

def geraJson():
	if str(os.path.isfile(path)) == "True":
		print("O arquivo jah existe")
	else:
		print("Obtendo Scan id...") 
		print(scanid)

		print("Solicitando informacoes ao Checkmarx...")
		urlReports = CheckmarxUrl + "/CxRestAPI/reports/sastScan"
		headersReports = { 'Content-Type': 'application/json;v=1.0','Accept': 'application/json;v=1.0', 'Authorization': gerarCxToken()}
		payloadReports = "{\"reportType\": \"XML\",\"scanId\": " + str(scanid) + "}"
		responseReports = requests.request("POST", urlReports, headers=headersReports, data = payloadReports)

		if responseReports.status_code == 202:
			json_data = json.loads(responseReports.text)
			reportId = json_data['reportId']
			print(str(reportId))
		else:
			print("Erro ao gerar relatório para o Checkmarx : " + responseReports.text)
			exit(1)

		print("Processando...")
		urlReportsStatus = CheckmarxUrl + "/CxRestAPI/reports/sastScan/" + str(reportId) + "/status"
		headersReportsStatus = { 'Content-Type': 'application/json;v=1.0','Accept': 'application/json;v=1.0', 'Authorization': gerarCxToken()}

		status = "In Process"
		while status != 'Created':
			responseReportsStatus = requests.request("GET", urlReportsStatus, headers=headersReportsStatus)
			if responseReportsStatus.status_code == 200:
				json_data = json.loads(responseReportsStatus.text)
				status = json_data['status']['value']
				print(status)
			else:
				print("Erro ao obter status relatorio do Checkmarx : " + responseReportsStatus.text)
				exit(1)

		print("Salvando resultados em JSON ...")
		urlReportXML = CheckmarxUrl + "/CxRestAPI/reports/sastScan/" + str(reportId)
		headersReportXML = { 'Content-Type': 'application/json;v=1.0','Accept': 'application/json;v=1.0', 'Authorization': gerarCxToken()}

		responseReportXML = requests.request("GET", urlReportXML, headers=headersReportXML)
		if responseReportXML.status_code == 200:
			o = xmltodict.parse(responseReportXML.text)
			file = open(path, "w")
			file.write(json.dumps(o))
			file.close()
			return "Informacoes obtidas"
		else:
			print("Erro ao salvar JSON : " + responseReportXML.text)
			exit(1)

print("Obtendo informacoes...")
geraJson()

print("Lendo resultados..")
with open(path) as f:
	json_data = json.load(f)
	
try:
	if isinstance(json_data['CxXMLResults']['Query'], list):
		for i in json_data['CxXMLResults']['Query']:
				if isinstance(i['Result'], list):
					for y in i['Result']:
						print("****************************************************************")
						print("Nome do projeto : " + json_data['CxXMLResults']['@ProjectName'])
						print("Time : " + json_data['CxXMLResults']['@TeamFullPathOnReportDate'])
						print("Data/hora do scan : " + json_data['CxXMLResults']['@ScanStart'])
						print("Vulnerabilidade : " + i['@name'])
						print("Link CWE : " + "https://cwe.mitre.org/data/definitions/" + str(i['@cweId']) + ".html")
						print("Severidade " + y['@Severity'])
						print("Falso positivo " + y['@FalsePositive'])
						print("Nome do arquivo " + y['@FileName'])
						print("Linha " + y['@Line'])
						print("Descricao" + getDescription(y['Path']['@ResultId'], y['Path']['@PathId']))
						print("****************************************************************")
				else:
					print("****************************************************************")
					print("Nome do projeto : " + json_data['CxXMLResults']['@ProjectName'])
					print("Time : " + json_data['CxXMLResults']['@TeamFullPathOnReportDate'])
					print("Data/hora do scan : " + json_data['CxXMLResults']['@ScanStart'])
					print("Vulnerabilidade : " + i['@name'])
					print("Link CWE : " + "https://cwe.mitre.org/data/definitions/" + str(i['@cweId']) + ".html")
					print("Severidade " + i['Result']['@Severity'])
					print("Falso positivo " + i['Result']['@FalsePositive'])
					print("Nome do arquivo " + i['Result']['@FileName'])
					print("Linha " + i['Result']['@Line'])
					print("Descricao" + getDescription(i['Result']['Path']['@ResultId'], i['Result']['Path']['@PathId']))
					print("****************************************************************")
	else:
		print("****************************************************************")
		print("Nome do projeto : " + json_data['CxXMLResults']['@ProjectName'])
		print("Time : " + json_data['CxXMLResults']['@TeamFullPathOnReportDate'])
		print("Data/hora do scan : " + json_data['CxXMLResults']['@ScanStart'])
		print("Vulnerabilidade :" + json_data['CxXMLResults']['Query']['@name'])
		print("Link CWE : " + "https://cwe.mitre.org/data/definitions/" + str(json_data['CxXMLResults']['Query']['@cweId']) + ".html")
		print("Severidade : " + json_data['CxXMLResults']['Query']['Result']['@Severity'])
		print("Falso positivo : " + json_data['CxXMLResults']['Query']['Result']['@FalsePositive'])
		print("Nome do arquivo :" + json_data['CxXMLResults']['Query']['Result']['@FileName'])
		print("Linha : " + json_data['CxXMLResults']['Query']['Result']['@Line'])
		print("Descricao :" + getDescription(json_data['CxXMLResults']['Query']['Result']['Path']['@ResultId'], json_data['CxXMLResults']['Query']['Result']['Path']['@PathId']))
		print("****************************************************************")
except KeyError:
	print("Sem vulnerabilidades")