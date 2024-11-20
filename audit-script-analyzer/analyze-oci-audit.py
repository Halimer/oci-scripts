from distutils.command.config import config
from fileinput import filename
import os, oci, dateutil, datetime, argparse, csv, pytz
 
# Credentials created before this date need to be rotated
EPOCH = dateutil.parser.parse('2022-01-19T18:45:00.000+00:00')

##########################################################################
# Runs the identity report
##########################################################################
def execute_identity_report():

    # Get Command Line Parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', default="", dest='config_profile', help='Config file section to use (tenancy profile)')
    parser.add_argument('-i', default="", dest='file_name', help='identity-audit--tool output file ex. "audit.csv"')
    parser.add_argument('--days', default=30, dest='days', help='Number of days back to look default is 30 days')
    parser.add_argument('--region', default="all", dest='region', help='Region to query to a single region default is all regions.')
    parser.add_argument('--all-compartments', action='store_true', default=False, dest='all_compartments', help='uery OCI Audit service in all compartments and root, default is root')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')

    cmd = parser.parse_args()

    start_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)
    start_datetime_str = str(start_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))
    
    print("Start time is: " + start_datetime_str)
    config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)

    analyze = analyze_audit(config, signer, cmd.file_name, int(cmd.days), cmd.region, cmd.all_compartments)
    analyze.read_identity_audit_output()
    analyze.collect_oci_audit_records()
    end_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)
    end_datetime_str = str(end_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))
    print("End Time is: " + end_datetime_str)

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



class analyze_audit:
    __users = []
    __user_ocids =[]
    __audit_records = []
    __compartments = []
    __regions = []
    # Start print time info
    __current_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)
    __current_datetime_str = str(__current_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))

    def __init__(self, config, signer, file_name, days, region, all_compartments):
        
        self.__file_name = file_name
        self.__config = config
        self.__signer = signer
        self.__region_to_query = region
        self.__all_compartments = all_compartments
        # Setting how many days back in audit to look
        self.__days_back_datetime = self.__current_datetime - datetime.timedelta(days=days)
        self.__days_back_datetime_str = str(self.__days_back_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))

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

        # Getting the list of compartments or just tenancy
        if all_compartments:
            self.__identity_read_compartments()
        else:
            self.__compartments.append(self.__tenancy)




    ##########################################################################
    # Loops through all compartments in 
    # Input - file_name of a CSV file created by the identity-audit-tools
    # Output - list of distinct users OCIDs from the 
    ##########################################################################
    def read_identity_audit_output(self):
        users = []
        try:
            with open(self.__file_name, 'r') as input:
                csvFile = csv.reader(input)
                
                # Getting user OCIDs from CSV file
                for user in csvFile:
                    users.append(user[3] + ":" + user[4])
                
        except Exception as e:
            raise("Input file not available: " + str(e))
        print(users)
        # Getting unique user OCIDs
        for user in set(users):
            split_user = user.split(":")
            user_record = {
                "user_name" : split_user[0],
                "user_ocid" : split_user[1],
                "last_login_" : {}
            }
            self.__users.append(user_record)
            self.__user_ocids.append(split_user[1])
        return self.__users
    
    def collect_oci_audit_records(self):
        start_time = self.__days_back_datetime_str
        end_time = self.__current_datetime_str
        next_record = ""
        for region in self.__regions:
            self.__config['region'] = region.region_name
            self.__signer.region_name = region.region_name
            print("Processing OCI Audit Records in region: " + region.region_name)
            try:
                    self.__audit_client = oci.audit.AuditClient(self.__config, signer=self.__signer)
                    # if proxy:
                    #     self.__cloud_guard.base_client.session.proxies = {'https': proxy}
            except Exception as e:
                raise("Failed to create audit client: " + str(e))
            for compartment in self.__compartments:
                print("\tProcessing OCI Audit Records in compartment: " + compartment.name)

                self.__audit_records += oci.pagination.list_call_get_all_results(
                        self.__audit_client.list_events,
                        compartment_id=compartment.id,
                        start_time=start_time,
                        end_time=end_time
                    ).data


                # while True:
                #     audit_records = self.__audit_client.list_events(compartment_id=compartment.id,start_time=start_time,end_time=end_time, page=next_record)
                #     next_record = audit_records.next_page
                #     for audit_record in audit_records.data:
                #         if (audit_record.data.identity.principal_id in self.__user_ocids):
                #             record = {
                #                 "identity_principal_name" : audit_record.data.identity.principal_name,
                #                 "identity_credentials" : audit_record.data.identity.credentials,                        
                #                 "event_time" : audit_record.event_time,
                #                 "compartment_id" : audit_record.data.compartment_id,
                #                 "compartment_name" : audit_record.data.compartment_name,
                #                 "identity_auth_type" : audit_record.data.identity.auth_type,
                #                 "identity_caller_id" : audit_record.data.identity.caller_id,
                #                 "identity_caller_name" : audit_record.data.identity.caller_name,
                #                 "identity_console_session_id" : audit_record.data.identity.console_session_id,
                #                 "identity_credentials" : audit_record.data.identity.credentials,
                #                 "identity_ip_address" : audit_record.data.identity.ip_address,
                #                 "identity_principal_id" : audit_record.data.identity.principal_id,
                #                 "identity_tenant_id" : audit_record.data.identity.tenant_id,
                #                 "identity_user_agent" : audit_record.data.identity.user_agent,
                #                 "event_id" : audit_record.event_id
                #             }
                #             self.__audit_records.append(record)

                #     if not next_record:
                #         break
                
        self.__print_to_csv_file(self.__tenancy.name,"audit_records", self.__audit_records)
        return self.__audit_records
    ##########################################################################
    # Print to CSV
    ##########################################################################
    def __print_to_csv_file(self, tenancy_name, file_subject, data):


        try:
            # if no data
            if len(data) == 0:
                return None
            
            # get the file name of the CSV
            
            file_name = tenancy_name + "_" + file_subject
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
    # Load compartments
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
            return self.__compartments

        except Exception as e:
            raise RuntimeError(
                "Error in identity_read_compartments: " + str(e.args))

execute_identity_report()