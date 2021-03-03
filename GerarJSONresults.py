# coding: latin-1
import requests,json,xmltodict,os.path

CheckmarxUrl = "https://cxprivatecloud.checkmarx.net"
scanid = '1001910'
user = 'gabriel.prevelate@nova-8.com'
pwd =  'Gabriel123@'

if str(os.path.isfile('C:\Users\Gabriel Prevelate\Desktop\cxresults.json')) == "True":
	print("O arquivo jah existe")
else:
	print("Obtendo Scan id do Json...") 
	print(scanid)

	print("Gerando token API Checkmarx...")
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
	else:
		print("Erro ao gerar token para o Checkmarx : " + responseToken.text)
		exit(1)

	print("Solicitando relatorio ao Checkmarx...")
	urlReports = CheckmarxUrl + "/CxRestAPI/reports/sastScan"
	headersReports = { 'Content-Type': 'application/json;v=1.0','Accept': 'application/json;v=1.0', 'Authorization': tokenCx}
	payloadReports = "{\"reportType\": \"XML\",\"scanId\": " + str(scanid) + "}"
	responseReports = requests.request("POST", urlReports, headers=headersReports, data = payloadReports)

	if responseReports.status_code == 202:
		json_data = json.loads(responseReports.text)
		reportId = json_data['reportId']
		print(str(reportId))
	else:
		print("Erro ao gerar relatório para o Checkmarx : " + responseReports.text)
		exit(1)

	print("Processando relatório...")
	urlReportsStatus = CheckmarxUrl + "/CxRestAPI/reports/sastScan/" + str(reportId) + "/status"
	headersReportsStatus = { 'Content-Type': 'application/json;v=1.0','Accept': 'application/json;v=1.0', 'Authorization': tokenCx}

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
	headersReportXML = { 'Content-Type': 'application/json;v=1.0','Accept': 'application/json;v=1.0', 'Authorization': tokenCx}

	responseReportXML = requests.request("GET", urlReportXML, headers=headersReportXML)
	if responseReportXML.status_code == 200:
		o = xmltodict.parse(responseReportXML.text)
		file = open(r'C:\Users\Rafaela\Desktop\cxresults.json', "w")
		file.write(json.dumps(o))
		file.close()
		print("Relatorio foi salvo")
	else:
		print("Erro ao salvar JSON : " + responseReportXML.text)
		exit(1)