## requires configparser
# pip3 install configparser
## requires requests
# pip3 install requests
## requires pycryptodome
# sudo apt-get install build-essential libgmp3-dev python3-dev
# pip3 install pycryptodomex
import configparser
import json
import requests
from datetime import datetime, timedelta


def initClient():
    ### Get the configuration from the CLIENT.CFG file
    config = configparser.ConfigParser()
    config.read('exampleConfig.cfg')
    ### Get the URL endpoint and config data
    myUri = config['casb']['uri']
    doDecrypt = config['casb']['crypt']
    myAccessKey = config['casb']['accessKey']
    mySecretKey = config['casb']['secretKey']

    ### If the doDecrypt flag is set, decrypt the keys
    if (doDecrypt == 'True'):
        myAccessKey = decryptValue(myAccessKey)
        mySecretKey = decryptValue(mySecretKey)
    ### Return the values required
    return ( myUri, myAccessKey, mySecretKey )

def decryptValue( myVal ):
    ### Placeholder for decryption
    print("decrypt", str(myVal))
    return myVal

def getCasbSession( myUrl, myAccess, mySecret ):
    ### Build the JSON for the request
    myReqJson = json.dumps( { 'accessKey':myAccess, 'accessSecret': mySecret } )
    #print("  JSON_Req", myReqJson)
    ### Build the headers for the request (content-type is required;cache-control is optional)
    headers = { 'content-type': "application/json", 'cache-control': "no-cache" }
    ### Set the URL to get the token
    myUrl = myUrl + "/api/v1/token"
    print("  myURL = ", str(myUrl))
    # POST the data and headers to the URL and get the response
    r = requests.post( myUrl, data=myReqJson, headers=headers)
    #print("  R Text: ", r.text)
    #print("  R Status Code: ", r.status_code)
    ### If the response was successful (HTTP 200)
    if r.status_code == 200:
        ### Decode the JSON and load it in a dict
        myRaw = json.loads(r.content.decode('utf-8'))
        #print("  Raw JSON: ", myRaw)
        #print("  Token: ", myRaw["accessToken"])
        #print("  Tenant ID: ", myRaw["tenantId"])
        ### Return the token and tenant information
        return myRaw["accessToken"], myRaw["tenantId"]
    else:
        return None, None

def getCasbAppInstance( myUrl, myHeaders, myInstance ):
    #print(" getCasbAppInstances")
    ### Set the URL to get the instances
    myUrl = myUrl + "/api/v1/applications"
    ### If the myInstance is empty...
    if not myInstance:
        ### Request ALL instances (no instance specified)
        r = requests.get(myUrl, headers=headers)
    else:
        ### Build the JSON for the requested instance
        myReqJson = json.dumps({'applicationInstanceId': myInstance})
        ### Request SINGLE instance
        r = requests.get(myUrl, data=myReqJson, headers=headers)
    #print("  R Text: ", r.text)
    #print("  R Status Code: ", r.status_code)
    ### If the response was successful (HTTP 200)
    if r.status_code == 200:
        ### Decode the JSON and load it in a dict
        myRaw = json.loads(r.content.decode('utf-8'))
        #print("  Raw JSON: ", json.dumps(myRaw, sort_keys=False, indent=4))
        return myRaw
    else:
        print("  getCasbAppInstance: HTTP response code: ", r.status_code )
        return None

def getManyEvents( myUrl, myHeaders, myDateStart, myDateEnd, myInstanceId ):
    print(" getManyEvents:")
    myUrl = myUrl + "/api/v1/events/riskevents"
    print("  myURL = ", str(myUrl))
    ### Date format     ISO-8601 Date format
    #                   yyyy-MM-ddThh:mm:ss.000Z
    #                   2017-08-15T04:00:00.000Z
    ### If there is no end date specified, set the myDateEnd to NOW
    if not myDateEnd:
        myDateEnd = datetime.utcnow().isoformat() + "Z"
    ### If there is no STARTING date, set the myDateStart to 1 week
    if not myDateStart:
        myD = datetime.today() - timedelta(days=20)
        myDateStart = myD.isoformat() + "Z"
    ### If there is no INSTANCE specified, get events for all services
    if not myInstanceId:
        ### Build the request parameters for the requested events for all instances
        myReqParams = {'startDate': myDateStart,
                                'endDate': myDateEnd}
        #myReqJson =     json.dumps(myReqParams)
    ### If there IS an INSTANCE specified, get events for only is instance
    else:
        ### Build the JSON for the requested instance from the date range
        myReqParams = {'startDate': myDateStart,
                                'endDate': myDateEnd,
                                'applicationInstanceId': myInstanceId}
        #myReqJson = json.dumps(myReqParams)
    print("  getEvents: Start ", str(myDateStart))
    print("  getEvents:   End ", str(myDateEnd))
    print("  getEvents: headers: ", str(myHeaders))
    #print("  getEvents: requestJson: ", str(myReqJson))
    print("  getEvents: Params: ", str(myReqParams))
    #r = requests.get(myUrl, data=myReqJson, headers=myHeaders)
    r = requests.get(myUrl, params=myReqParams, headers=myHeaders)
    print("  R URL: ", r.url)
    #print("  R Text: ", r.text)
    print("  R Status Code: ", r.status_code)
    ### If the response was successful (HTTP 200)
    if r.status_code == 200:
        ### Decode the JSON and load it in a dict
        myRaw = json.loads(r.content.decode('utf-8'))
        print("  Raw JSON: ", json.dumps(myRaw, sort_keys=False, indent=4))
        #return myRaw
    else:
        print("  getManyEvents: HTTP response code: ", r.status_code )
        #return Non


### MAIN
if __name__ == '__main__':
    print("Start : ", datetime.utcnow().isoformat() + "Z")
    url = ''
    accessKey = ''
    secretKey = ''
    (url, accessKey, secretKey) = initClient()
    print("URL Base = ", str(url))
    #print("AccessKey = ", str(accessKey))
    #print("SecretKey = ", str(secretKey))
    (session, tenant) = getCasbSession( url, accessKey, secretKey )
    print(" Session:", str(session))
    print(" Tenant: ", str(tenant))

    ### Make a session header for the requests
    ### All headers except 'cache-control' are required
    ### Note that the "Authorization" header's value must
    ### have the "Bearer" prefix to the session
    headers = {'content-type': "application/json", 'cache-control': "no-cache",
               'X-Apprity-Tenant-Id': tenant, 'Authorization': 'Bearer ' + session }
    #print("Headers: ", str(headers))

    ### Get all instance data (no specified instance will pull all)
    apps = getCasbAppInstance( url, headers, '' )
    ### Print the returned data
    #print("  Raw JSON: ", json.dumps(apps, sort_keys=False, indent=4))

    ### Get an instanceID in case we want to use it for a specific group of events
    myInstance = apps['application'][0]['instanceName']
    myInstanceId = apps['application'][0]['instanceId']
    print(" myInstance:   ", myInstance)
    print(" myInstanceId: ", myInstanceId)

    ### Get all events for all services (limited to max number of dats [20] in the script)
    #events = getManyEvents( url, headers, '', '', '' )

    ### Get all events for 1 service (limited to max number of days [20] in the script)
    events = getManyEvents( url, headers, '', '', myInstanceId)
    print("Done at ", datetime.utcnow().isoformat() + "Z")
