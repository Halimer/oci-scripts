# from distutils.command.config import config
from fileinput import filename
import os, oci, dateutil, datetime, argparse, csv, pytz
from datetime import timedelta, date, datetime
from threading import Thread
import json

# Credentials created before this date need to be rotated
EPOCH = dateutil.parser.parse('2022-01-19T18:45:00.000+00:00')

class analyze_audit:
    __batch_size = 10
    __compartments = []
    __compartments_list = []
    __regions = []
    __audit_records = []
    __query_list = []
    # Start print time info
    __current_datetime = datetime.now().replace(tzinfo=pytz.UTC)
    __current_datetime_str = str(__current_datetime.strftime("%Y_%m_%d_%H_%M"))

    def __init__(self, config, signer, file_name, days, region, startdate, enddate, user_ocid):

        start_year, start_month, start_day = map(int, startdate.split("-")) 
        end_year, end_month, end_day = map(int, enddate.split("-")) 
        start_date = date(start_year, start_month, start_day)
        end_date = date(end_year, end_month, end_day)
        
        self.__start_date = start_date
        self.__end_date = end_date

        self.__file_name = file_name
        self.__config = config
        self.__signer = signer
        self.__region_to_query = region

        try:
            self.__identity_client = oci.identity.IdentityClient(config, signer=signer)
            self.__tenancy =  self.__identity_client.get_tenancy(config["tenancy"]).data
        except Exception as e:
            raise("Failed to create identity client: " + str(e))
        
        try:
            self.__regions = self.__identity_client.list_region_subscriptions(self.__tenancy.id).data
        except Exception as e:
            raise("Failed to get list of subscribed regions: " + str(e))
       
        if self.__region_to_query != "all":
            for region in self.__regions:
                if self.__region_to_query == region.region_name:
                    self.__regions = []
                    self.__regions.append(region)
            if len(self.__regions) == 0:
                raise("Region name provided is not a subscribed region or doesn't exist: " + self.__region_to_query)
        
        # Setting the Retry Strategy for all query types
        self.__retry_strategy = self.__get_retry_strategy()
        
        if user_ocid:
            self.__user_ocid = user_ocid
            print(f'Querying for User OCID: {user_ocid}')
            self.__query_user_ocid_search()
        else:
            print(f'Querying all audit records, this may take a while')
            self.__query_all_audit_logs_search()
        print(f'Date Range is: {self.__start_date} to {self.__end_date}')
        
    ##########################################################################
    # Orcehstration for Full Tenancy Audit Extraction
    ##########################################################################
    def __query_all_audit_logs_search(self):
        #Going to search All longs in the tenancy day by day
        self.__date_ranges = get_date_ranges(self.__start_date, self.__end_date, [], chunk=1)
        print(self.__date_ranges)
        # print(self.__tenancy.id)
        all_compartments_str = str(self.__tenancy.id) + "/_Audit_Include_Subcompartment"
        # print(all_compartments_str)
        search_query = 'search ' + '"' + all_compartments_str + '"' + """ | select type, data.identity.principalId, data.compartmentId, data.compartmentName, data.identity.ipAddress, data.identity.principalName, data.eventName, data.resourceId, data.identity.userAgent, datetime, id, data.identity.credentials """
        print(search_query)
        self.__query_list.append(search_query)

        threads = []
        for dates in self.__date_ranges:
            start_date_str = str(dates['start_date'])
            end_date_str = str(dates['end_date'])
            start_time_dt =  datetime.strptime(start_date_str + "T00:00:00.000000Z", "%Y-%m-%dT%H:%M:%S.%fZ")
            end_time_dt =  datetime.strptime(end_date_str + "T23:59:59.000000Z", "%Y-%m-%dT%H:%M:%S.%fZ")

            thread = Thread(target=self.__run_tenancy_logging_search_query, args=(start_time_dt, end_time_dt))
            threads.append(thread)

        print("Processing Audit Logs...")
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


    ##########################################################################
    # Orcehstration for User OCID Search
    ##########################################################################
    def __query_user_ocid_search(self):
        self.__date_ranges = get_date_ranges(self.__start_date, self.__end_date, [])
        # Getting the list of compartments or just tenancy
        self.__identity_read_compartments()
        

        # print(self.__compartments_list)
        self.__query_list = self.__build_compartment_search_queries(tenancy_ocid=self.__tenancy.id,
                                                user_ocid=self.__user_ocid)

        

        # print(date_ranges)

        threads = []
        for dates in self.__date_ranges:
            start_date_str = str(dates['start_date'])
            end_date_str = str(dates['end_date'])
            start_time_dt =  datetime.strptime(start_date_str + "T00:00:00.000000Z", "%Y-%m-%dT%H:%M:%S.%fZ")
            end_time_dt =  datetime.strptime(end_date_str + "T23:59:59.000000Z", "%Y-%m-%dT%H:%M:%S.%fZ")

            thread = Thread(target=self.__run_userocid_logging_search_query, args=(start_time_dt, end_time_dt))
            threads.append(thread)

        print("Processing Audit Logs...")
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        self.print_to_csv_file(self.__tenancy.name, "audit-log", self.__audit_records)
        self.print_to_json_file(self.__tenancy.name, "audit-log", self.__audit_records)

    ##########################################################################
    # Builds Searches for User OCID Search
    ##########################################################################
    def __build_compartment_search_queries(self, user_ocid, tenancy_ocid):
        num_batches = (len(self.__compartments) + self.__batch_size - 1) // self.__batch_size
        # print("*" * 80)
        # print(num_batches)
        batches = [self.__compartments_list[i*self.__batch_size:(i+1)*self.__batch_size] for i in range(num_batches)]
        query_list = []
        for batch in batches:
            compartment_str = '/_Audit" "'.join(batch)
            compartment_str = "\"" + compartment_str + "/_Audit\""
            search_query = "search " + compartment_str + """ | data.identity.principalId = '""" + user_ocid + """' and data.identity.tenantId = '""" + tenancy_ocid + """' | select type, data.identity.principalId, data.compartmentId, data.compartmentName, data.identity.ipAddress, data.identity.principalName, data.eventName, data.resourceId, data.identity.userAgent, datetime, id, data.identity.credentials """
            
            query_list.append(search_query)

        
        return query_list
    
    ##########################################################################
    # Orcehstration for Full Tenancy Audit Extraction
    ##########################################################################
    def __run_tenancy_logging_search_query(self, query_start_time_dt, query_end_time_dt):
        
        try:
            logging_search_client = oci.loggingsearch.LogSearchClient(config=self.__config,
                                                                      signer=self.__signer,
                                                                      timeout=10000, 
                                                                      retry_strategy=self.__retry_strategy)
            print(str(query_start_time_dt))
            filename = self.__tenancy.name + "-" + "audit-" + \
                str(query_start_time_dt).split(" ")[0] + "-to-" +\
                 str(query_end_time_dt).split(" ")[0] + "-ext-" + self.__current_datetime_str + ".json"
            print(filename)
            log_file = open(filename, 'w')

            for query in self.__query_list:

                page = None
                while True:
                    response = logging_search_client.search_logs(
                        search_logs_details=oci.loggingsearch.models.SearchLogsDetails(
                            search_query=query,
                            time_start=query_start_time_dt,
                            time_end=query_end_time_dt,
                            is_return_field_info=False),
                        limit=1000,
                        page=page)
                    audit_logs = response.data
                    if audit_logs.summary.result_count > 0:
                        
                        print("\t Found " + str(audit_logs.summary.result_count) + " audit events")
                        for result in audit_logs.results:
                            record = result.data
                            record = oci.util.to_dict(record)
                            json_object = json.dumps(record)
                            # Writing record to file
                            log_file.write(json_object + ",\n")

                    if response.has_next_page:
                        page = response.next_page
                    else:
                        break
            
            log_file.close()

        except Exception as e:
            print("Exception is : " + str(e))

    ##########################################################################
    # Iterates through compartment list to build queries for User OCID search
    ##########################################################################
    def __run_userocid_logging_search_query(self, query_start_time_dt, query_end_time_dt):
        
        try:
            logging_search_client = oci.loggingsearch.LogSearchClient(config=self.__config,
                                                                      signer=self.__signer,
                                                                      timeout=10000, 
                                                                      retry_strategy=self.__retry_strategy)
            for query in self.__query_list:

                page = None
                while True:
                    response = logging_search_client.search_logs(
                        search_logs_details=oci.loggingsearch.models.SearchLogsDetails(
                            search_query=query,
                            time_start=query_start_time_dt,
                            time_end=query_end_time_dt,
                            is_return_field_info=False),
                        limit=1000,
                        page=page)
                    audit_logs = response.data
                    if audit_logs.summary.result_count > 0:
                        
                        print("\t Found " + str(audit_logs.summary.result_count) + " audit events")
                        for result in audit_logs.results:
                            # userInfo = {
                            #             "id" : result.data["id"],
                            #             "type" : result.data["type"],
                            #             "time" : datetime.fromtimestamp(result.data["datetime"]/1000.0).strftime('%Y-%m-%d %H:%M:%S.%f'), # converting epoch time
                            #             "principalName" : result.data["data.identity.principalName"], 
                            #             "principalId" : result.data["data.identity.principalId"], 
                            #             "credentials" : result.data["data.identity.credentials"],
                            #             "compartmentId" : result.data["data.compartmentId"], 
                            #             "compartmentName" : result.data["data.compartmentName"], 
                            #             "ipAddress" : result.data["data.identity.ipAddress"], 
                            #             "principalName" : result.data["data.identity.principalName"],  
                            #             "eventName" : result.data["data.eventName"], 
                            #             "resourceId" : result.data["data.resourceId"], 
                            #             "userAgent" : result.data["data.identity.userAgent"], 
                            #             "tenancy" : self.__tenancy.id}
                            record = oci.util.to_dict(result)
                            # print(userInfo)
                            self.__audit_records.append(record)
                    if response.has_next_page:
                        page = response.next_page
                    else:
                        break
    
        except Exception as e:
            print("Exception is : " + str(e))
    
    
    ##########################################################################
    # Print to CSV
    ##########################################################################
    def print_to_csv_file(self, tenancy_name, file_subject, data):


        try:
            # if no data
            if len(data) == 0:
                return None
            
            # get the file name of the CSV
            
            file_name = tenancy_name + "_" + file_subject + "_" + self.__current_datetime_str
            file_name = (file_name.replace(" ", "_")
                            ).replace(".", "-") + ".csv"
            file_path = os.path.join(file_name)

            # add start_date to each dictionary
            result = [dict(item, extract_date=self.__current_datetime_str)
                        for item in data]

            # generate fields
            fields = [key for key in result[0].keys()]

            with open(file_path, mode='w', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fields)

                # write header
                writer.writeheader()

                for row in result:
                    writer.writerow(row)
                    #print(row)

            print("CSV: " + file_subject.ljust(22) + " --> " + file_path)
            # Used by Upload
                
            return file_path
            
        except Exception as e:
            raise Exception("Error in print_to_csv_file: " + str(e.args))

    ##########################################################################
    # Print to JSON
    ##########################################################################
    def print_to_json_file(self, tenancy_name, file_subject, data):

        try:
            # if no data
            if len(data) == 0:
                return None
            
            # get the file name of the JSON
            file_name = tenancy_name + "_" + file_subject + "_" + self.__current_datetime_str
            file_name = (file_name.replace(" ", "_")).replace(".", "-") + ".json"
            file_path = os.path.join(file_name)
            # Serializing JSON to string
            json_object = json.dumps(data, indent=4)
          
            # If this flag is set all OCIDs are Hashed to redact them
            # Writing to json file
            with open(file_path, mode='w', newline='') as json_file:
                json_file.write(json_object)
            
            print("JSON: " + file_subject.ljust(22) + " --> " + file_path)
            
            # Used by Upload
            return file_path
        
        except Exception as e:
            raise Exception("Error in print_to_json_file: " + str(e.args))
    
    ##########################################################################
    # Load compartments for User OCID Only
    ##########################################################################
    def __identity_read_compartments(self):
        print("Processing Compartments...")
        try:
            self.__compartments = oci.pagination.list_call_get_all_results(
                self.__identity_client.list_compartments,
                self.__tenancy.id,
                compartment_id_in_subtree=True,
                lifecycle_state = "ACTIVE"
            ).data

            # Add root compartment which is not part of the list_compartments
            self.__compartments.append(self.__tenancy)

            print("Processed " + str(len(self.__compartments)) + " Compartments")                        
            
            for compartment in self.__compartments:
                self.__compartments_list.append(compartment.id)
            
            return self.__compartments

        except Exception as e:
            raise RuntimeError(
                "Error in identity_read_compartments: " + str(e.args))

    ##########################################################################
    # Build Retry Strategy for All Search Types
    ##########################################################################
    def __get_retry_strategy(self):
        custom_retry_strategy = oci.retry.RetryStrategyBuilder(
            # Make up to 5 service calls
            max_attempts_check=True,
            max_attempts=5,

            # Don't exceed a total of 60 seconds for all service calls
            total_elapsed_time_check=True,
            total_elapsed_time_seconds=60,

            # Wait 15 seconds between attempts
            retry_max_wait_between_calls_seconds=15,

            # Use 2 seconds as the base number for doing sleep time calculations
            retry_base_sleep_time_seconds=2,

            # Retry on certain service errors:
            #
            #   - 5xx code received for the request
            #   - Any 429 (this is signified by the empty array in the retry config)
            #   - 400s where the code is QuotaExceeded or LimitExceeded
            service_error_check=True,
            service_error_retry_on_any_5xx=True,
            service_error_retry_config={
                429: []
            },

            # Use exponential backoff and retry with full jitter, but on throttles use
            # exponential backoff and retry with equal jitter
            backoff_type=oci.retry.BACKOFF_FULL_JITTER_EQUAL_ON_THROTTLE_VALUE
        ).get_retry_strategy()
        return custom_retry_strategy

def numOfDays(date1, date2):
#check which date is greater to avoid days output in -ve number
    if date2 > date1:   
        return (date2-date1).days
    else:
        return (date1-date2).days
    
def get_date_ranges(start_date, end_date, date_ranges, chunk=3):
    days_between = numOfDays(start_date, end_date)
    print("Chunk is: " + str(chunk))
    if days_between > chunk:
            # print("Days between over 13 is: " + str(days_between))
            next_date = start_date + timedelta(days=chunk)
            # print(next_date)
            date_ranges.append({"start_date" : start_date, "end_date" : next_date})
            return get_date_ranges(next_date + timedelta(days=1), end_date, date_ranges, chunk=chunk)
    else:
        # print("Days between under 13 is: " + str(days_between))
        #next_date = start_date + timedelta(days=days_between)
        date_ranges.append({"start_date" : start_date, "end_date" : end_date})
        return date_ranges

##########################################################################
# Create signer for Authentication
# Input - config_profile and is_instance_principals and is_delegation_token
# Output - config and signer objects
##########################################################################
def create_signer(config_profile, is_instance_principals, is_delegation_token):

    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            print("Error obtaining instance principals certificate, aborting")
            raise SystemExit

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)
                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
            raise SystemExit

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:
        config = oci.config.from_file(
            oci.config.DEFAULT_LOCATION,
            (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
        )
        signer = oci.signer.Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config.get("key_file"),
            pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
            private_key_content=config.get("key_content")
        )
        return config, signer

##########################################################################
# Runs the identity report
##########################################################################
def execute_identity_report():

    # Get Command Line Parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', default="", dest='config_profile', help='Config file section to use (tenancy profile)')
    parser.add_argument('-i', default="", dest='file_name', help='Currenlty not used')
    parser.add_argument('--startdate', default="", dest='startdate', required=True, help='Start Date example: 2024-09-01')
    parser.add_argument('--enddate', default="", dest='enddate', required=True, help='End Date example: 2024-10-10')
    parser.add_argument('--userid', default="", dest='userid', help='User OCID example: ocid1.user.oc1..')
    # parser.add_argument('--region', default="all", dest='region', help='Region to query to a single region default is all regions.')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')

    cmd = parser.parse_args()

    

    start_datetime = datetime.now().replace(tzinfo=pytz.UTC)
    start_datetime_str = str(start_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))
    
    print("Start time is: " + start_datetime_str)
    config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)

    analyze = analyze_audit(config, signer, cmd.file_name, 0, "", cmd.startdate, cmd.enddate, cmd.userid)
    # analyze.read_identity_audit_output()
    # analyze.collect_oci_audit_records()
    end_datetime = datetime.now().replace(tzinfo=pytz.UTC)
    end_datetime_str = str(end_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))
    print("Start Times: " + start_datetime_str)
    print("End Time is: " + end_datetime_str)
    print("Runtime was: " + str(end_datetime - start_datetime))


execute_identity_report()