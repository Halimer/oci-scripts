# from distutils.command.config import config
from fileinput import filename
import os, oci, dateutil, datetime, argparse, csv, pytz
from datetime import timedelta, date, datetime
from threading import Thread
import json
import requests

# Credentials created before this date need to be rotated
EPOCH = dateutil.parser.parse('2022-01-19T18:45:00.000+00:00')
DEBUG = False

def debug(message):
    if DEBUG:
        print(f"Debug: {message}")

class analyze_audit:
    __regions = []
    __compartments = []
    __raw_compartment = []
    __domain_list_csv = []
    __domain_to_app_dict = {}

    # Start print time info
    __iso_time_format = "%Y-%m-%dT%H:%M:%S"
    __current_datetime = datetime.now().replace(tzinfo=pytz.UTC)
    __current_datetime_str = str(__current_datetime.strftime("%Y_%m_%d_%H_%M"))

    def __init__(self, config, signer, proxy=None):

        # OCI Link
        self.__oci_cloud_url = "https://cloud.oracle.com"
        self.__oci_users_uri = self.__oci_cloud_url + "/identity/users/"
        self.__oci_policies_uri = self.__oci_cloud_url + "/identity/policies/"
        self.__oci_groups_uri = self.__oci_cloud_url + "/identity/groups/"
        self.__oci_dynamic_groups_uri = self.__oci_cloud_url + "/identity/dynamicgroups/"
        self.__oci_identity_domains_uri = self.__oci_cloud_url + '/identity/domains/'
        # self.__oci_buckets_uri = self.__oci_cloud_url + "/object-storage/buckets/"
        # self.__oci_boot_volumes_uri = self.__oci_cloud_url + "/block-storage/boot-volumes/"
        # self.__oci_block_volumes_uri = self.__oci_cloud_url + "/block-storage/volumes/"
        # self.__oci_fss_uri = self.__oci_cloud_url + "/fss/file-systems/"
        # self.__oci_networking_uri = self.__oci_cloud_url + "/networking/vcns/"
        # self.__oci_network_capturefilter_uri = self.__oci_cloud_url + "/networking/network-command-center/capture-filters/"
        # self.__oci_adb_uri = self.__oci_cloud_url + "/db/adb/"
        # self.__oci_oicinstance_uri = self.__oci_cloud_url + "/oic/integration-instances/"
        # self.__oci_oacinstance_uri = self.__oci_cloud_url + "/analytics/instances/"
        self.__oci_compartment_uri = self.__oci_cloud_url + "/identity/compartments/"
        # self.__oci_drg_uri = self.__oci_cloud_url + "/networking/drgs/"
        # self.__oci_cpe_uri = self.__oci_cloud_url + "/networking/cpes/"
        # self.__oci_ipsec_uri = self.__oci_cloud_url + "/networking/vpn-connections/"
        # self.__oci_events_uri = self.__oci_cloud_url + "/events/rules/"
        # self.__oci_loggroup_uri = self.__oci_cloud_url + "/logging/log-groups/"
        # self.__oci_vault_uri = self.__oci_cloud_url + "/security/kms/vaults/"
        # self.__oci_budget_uri = self.__oci_cloud_url + "/usage/budgets/"
        # self.__oci_cgtarget_uri = self.__oci_cloud_url + "/cloud-guard/targets/"
        # self.__oci_onssub_uri = self.__oci_cloud_url + "/notification/subscriptions/"
        # self.__oci_serviceconnector_uri = self.__oci_cloud_url + "/connector-hub/service-connectors/"
        # self.__oci_fastconnect_uri = self.__oci_cloud_url + "/networking/fast-connect/virtual-circuit/"
        # self.__oci_instances_uri = self.__oci_cloud_url + "/compute/instances/"
        # self.__oci_cert_uri = self.__oci_cloud_url + "/security/certificates/certificate/"

        self.__config = config
        self.__signer = signer
        self.__proxy = proxy
        # For Region
        self.__regions = {}
        self.__raw_regions = []
        self.__home_region = None

        self.__identity_domains = []
        
        try:

            self.__identity = oci.identity.IdentityClient(
                self.__config, signer=self.__signer)
            if proxy:
                self.__identity.base_client.session.proxies = {'https': proxy}

            # Getting Tenancy Data and Region data
            self.__tenancy = self.__identity.get_tenancy(
                config["tenancy"]).data
            regions = self.__identity.list_region_subscriptions(
                self.__tenancy.id).data
        except Exception as e:
            raise RuntimeError("Failed to get identity information." + str(e.args))

        # Creating a record for home region and a list of all regions including the home region
        for region in regions:
            if region.is_home_region:
                self.__home_region = region.region_name
                print("Home region for tenancy is " + self.__home_region)
                if self.__home_region != self.__config['region']:               
                    print("It is recommended to run the CIS Complaince script in your home region")
                    print("The current region is: " + self.__config['region'])

                self.__regions[region.region_name] = {
                    "is_home_region": region.is_home_region,
                    "region_key": region.region_key,
                    "region_name": region.region_name,
                    "status": region.status,
                    "identity_client": self.__identity,
                }
            else:
                self.__regions[region.region_name] = {
                    "is_home_region": region.is_home_region,
                    "region_key": region.region_key,
                    "region_name": region.region_name,
                    "status": region.status,
                }
            
            
            record = {
                "is_home_region": region.is_home_region,
                "region_key": region.region_key,
                "region_name": region.region_name,
                "status": region.status,
            }
            self.__raw_regions.append(record)



        # Creating signers and config for all regions
        self.__create_regional_signers(proxy)



        # Setting the Retry Strategy for all query types
        self.__retry_strategy = self.__get_retry_strategy()
        
        
##########################################################################
# Create Client config
##########################################################################
    def __create_client(self, client, service_endpoint=None, key=None, proxy=None, connection_timeout=10, read_timeout=60):
        # Create client with optional service endpoint
        if service_endpoint:
            created_client = client(
                self.__config,
                signer=self.__signer,
                service_endpoint=service_endpoint,
                timeout=(connection_timeout, read_timeout)
            )
        else:
            created_client = client(
                self.__config,
                signer=self.__signer,
                timeout=(connection_timeout, read_timeout)
            )

        # Add proxy if configured
        if proxy:
            created_client.base_client.session.proxies = {'https': proxy}

        return created_client

##########################################################################
# Create regional config, signers and append them to self.__regions object 
##########################################################################
    def __create_regional_signers(self, proxy):
        print("Creating regional signers and configs...")
        for region_key, region_values in self.__regions.items():
            try:
                debug("processing __create_regional_signers")

                # Set regional config and signer
                region_signer = self.__signer
                region_signer.region_name = region_key
                region_config = self.__config
                region_config['region'] = region_key

                region_values['identity_client'] = self.__create_client(oci.identity.IdentityClient, key="identity", proxy=proxy)
                # region_values['audit_client'] = self.__create_client(oci.audit.AuditClient, key="audit", proxy=proxy)
                # region_values['cloud_guard_client'] = self.__create_client(oci.cloud_guard.CloudGuardClient, key="cloud_guard", proxy=proxy)
                # region_values['search_client'] = self.__create_client(oci.resource_search.ResourceSearchClient, key="resource_search", proxy=proxy)
                # region_values['network_client'] = self.__create_client(oci.core.VirtualNetworkClient, key="vcn", proxy=proxy)
                # region_values['events_client'] = self.__create_client(oci.events.EventsClient, key="events", proxy=proxy)
                # region_values['logging_client'] = self.__create_client(oci.logging.LoggingManagementClient, key="logging", proxy=proxy)
                # region_values['os_client'] = self.__create_client(oci.object_storage.ObjectStorageClient, key="object_storage", proxy=proxy)
                # region_values['vault_client'] = self.__create_client(oci.key_management.KmsVaultClient, key="vault", proxy=proxy)
                # region_values['ons_subs_client'] = self.__create_client(oci.ons.NotificationDataPlaneClient, key="ons", proxy=proxy)
                # region_values['adb_client'] = self.__create_client(oci.database.DatabaseClient, key="adb", proxy=proxy)
                # region_values['oac_client'] = self.__create_client(oci.analytics.AnalyticsClient, key="oac", proxy=proxy)
                # region_values['oic_client'] = self.__create_client(oci.integration.IntegrationInstanceClient, key="oic", proxy=proxy)
                # region_values['bv_client'] = self.__create_client(oci.core.BlockstorageClient, key="blockstorage", proxy=proxy)
                # region_values['fss_client'] = self.__create_client(oci.file_storage.FileStorageClient, key="fss", proxy=proxy)
                # region_values['sch_client'] = self.__create_client(oci.sch.ServiceConnectorClient, key="sch", proxy=proxy)
                # region_values['instance'] = self.__create_client(oci.core.ComputeClient, key="compute", proxy=proxy)
                # region_values['certificate_client'] = self.__create_client(oci.certificates_management.CertificatesManagementClient, key="cert_mgmt", proxy=proxy)

            except Exception as e:
                debug("__create_regional_signers: error reading " + str(self.__config))
                self.__errors.append({"id": "__create_regional_signers", "error": str(e)})
                raise RuntimeError("Failed to create regional clients for data collection: " + str(e))
    
    
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
    # Load compartments
    ##########################################################################
    def __identity_read_compartments(self):
        print("\nProcessing Compartments...")
        self.__compartments = []
        try:
            debug("__identity_read_compartments: Processing Compartments:")
            self.__compartments += oci.pagination.list_call_get_all_results(
                self.__regions[self.__home_region]['identity_client'].list_compartments,
                compartment_id=self.__tenancy.id,
                compartment_id_in_subtree=True,
                lifecycle_state="ACTIVE"
            ).data

            # Need to convert for raw output
            for compartment in self.__compartments:
                debug("__identity_read_compartments: Getting Compartments: " + compartment.name)
                deep_link = self.__oci_compartment_uri + compartment.id
                record = {
                    'id': compartment.id,
                    'name': compartment.name,
                    "deep_link": deep_link,
                    'compartment_id': compartment.compartment_id,
                    'defined_tags': compartment.defined_tags,
                    "description": compartment.description,
                    "freeform_tags": compartment.freeform_tags,
                    "inactive_status": compartment.inactive_status,
                    "is_accessible": compartment.is_accessible,
                    "lifecycle_state": compartment.lifecycle_state,
                    "time_created": compartment.time_created.strftime(self.__iso_time_format),
                    "region": ""
                }
                self.__raw_compartment.append(record)

            # Add root compartment which is not part of the list_compartments
            self.__compartments.append(self.__tenancy)
            deep_link = self.__oci_compartment_uri + self.__tenancy.id
            root_compartment = {
                "id": self.__tenancy.id,
                "name": self.__tenancy.name,
                "deep_link": deep_link,
                "compartment_id": "(root)",
                "defined_tags": self.__tenancy.defined_tags,
                "description": self.__tenancy.description,
                "freeform_tags": self.__tenancy.freeform_tags,
                "inactive_status": "",
                "is_accessible": "",
                "lifecycle_state": "",
                "time_created": "",
                "region": ""

            }
            self.__raw_compartment.append(root_compartment)

            print("\tProcessed " + str(len(self.__compartments)) + " Compartments")
            return self.__compartments

        except Exception as e:
            debug("__identity_read_compartments: Error Getting Compartments: " + compartment.name)
            # self.__errors.append({"id" : "__identity_read_compartments", "error" : str(e)})
            raise RuntimeError(
                "Error in identity_read_compartments: " + str(e.args))

    ##########################################################################
    # Load Identity Domains
    ##########################################################################
    def __identity_read_domains(self):
        print("Processing Identity Domains...")
        raw_identity_domains = []
        # Finding all Identity Domains in the tenancy
        for compartment in self.__compartments:
            try:
                debug("__identity_read_domains: Getting Identity Domains for Compartment: " + str(compartment.name))

                raw_identity_domains += oci.pagination.list_call_get_all_results(
                        self.__regions[self.__home_region]['identity_client'].list_domains,
                        compartment_id = compartment.id,
                        lifecycle_state = "ACTIVE"
                    ).data

            except Exception as e:
                debug("__identity_read_domains: Exception collecting Identity Domains\n" + str(e))
                # If this fails the tenancy likely doesn't have identity domains or the permissions are off

        for domain in raw_identity_domains:
            debug("__identity_read_domains: Getting password policy for domain: " + domain.display_name)
            domain_dict = oci.util.to_dict(domain)
            try: 
                debug("__identity_read_domains: Getting Identity Domain Password Policy for: " +  domain.display_name)
                idcs_url = domain.url + "/admin/v1/PasswordPolicies/PasswordPolicy" 
                raw_pwd_policy_resp = requests.get(url=idcs_url, auth=self.__signer)
                raw_pwd_policy_dict = json.loads(raw_pwd_policy_resp.content)
                debug("__identity_read_domains: Recieved Identity Domain Password Policy for: " +  domain.display_name)
                
                # Creating Identity Domains Client and storing it
                debug("__identity_read_domains: Creating Identity Domain Client for: " +  domain.display_name)
                domain_dict['IdentityDomainClient'] = oci.identity_domains.IdentityDomainsClient(\
                     config=self.__config, signer=self.__signer, service_endpoint=domain.url)
                debug("__identity_read_domains: Created Identity Domain Client for: " +  domain.display_name)

                pwd_policy_dict =  oci.util.to_dict(domain_dict['IdentityDomainClient'].get_password_policy(\
                        password_policy_id=raw_pwd_policy_dict['ocid']).data)
                
                domain_dict['password_policy'] = pwd_policy_dict
                domain_dict['errors'] = None 
                self.__identity_domains.append(domain_dict)
                debug("-" * 100)
                debug(f"__identity_read_domains: Domain Dict is: {domain_dict}")

            except Exception as e:
                debug("Identity Domains Error is for domain " + domain.display_name + "\n" + str(e))
                domain_dict['password_policy'] = None
                domain_dict['errors'] = str(e)
            

        print("\tProcessed " + str(len(self.__identity_domains)) + " Identity Domains")                        
        return 
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

    ##########################################################################
    # Identity Domains Helper function for pagination
    ##########################################################################
    def __identity_domains_get_all_results(self, func, args):
                
        if "start_index" not in args:
            args['start_index'] = 1
        if "count" not in args:
            args["count"] = 1000     
        if "filter" not in args:
            args["filter"] = ''
        if "attribute_sets" not in args:
            args["attribute_sets"] = ['all']

        debug("__identity_domains_get_all_results: " + str(func.__name__) + " arguments are: " + str(args))

        result = func(start_index=args['start_index'],
                    count=args['count'],
                    filter=args['filter'],
                     attribute_sets=args['attribute_sets']).data
        resources = result.resources
        while len(resources) < result.total_results:
            args["start_index"] = len(resources) + 1
            result = func(start_index=args['start_index'],
                    count=args['count'],
                    filter=args['filter'],
                    attribute_sets=args['attribute_sets']).data
            for item in result.resources:
                resources.append(item)

        return resources
        

    ##########################################################################
    # Lists Apps in identity Domain
    ##########################################################################
    def __identity_domain_read_apps(self):
        for domain in self.__identity_domains:
            apps = self.__identity_domains_get_all_results(
                domain['IdentityDomainClient'].list_apps,
                args={})
            for app in apps:
                app_dict = oci.util.to_dict(app)
                record = {
                    "id" : app.id,
                    "domain_name" : domain['display_name'],
                    "display_name" : app.display_name,
                    "description" : app.description,
                    "app_client_type" : app.client_type,
                    "app_is_managed_app" : app.is_managed_app,
                    "app_is_o_auth_client" : app.is_o_auth_client,
                    "app_is_o_auth_resource" : app.is_o_auth_resource,
                    "app_is_opc_service" : app.is_opc_service,
                    "app_allowed_scopes" : app.allowed_scopes,
                    "app_trust_scope" : app.trust_scope,
                    "app_allowed_roles" : app.allowed_grants,
                    "app_grants" : app.grants,
                    "app_granted_app_roles" : app.granted_app_roles,                    
                    "domain_ocid" : app.domain_ocid,
                    "domain_deeplink" : domain['url'],
                }
                self.__domain_list_csv.append(record)
                self.__domain_to_app_dict[app.id] = app_dict
                
    ##########################################################################
    # Orchestrator Method
    ##########################################################################
    def collect_apps(self):
        self.__create_regional_signers(proxy=self.__proxy)
        self.__identity_read_compartments()
        self.__identity_read_domains()
        self.__identity_domain_read_apps()
        self.print_to_csv_file(tenancy_name="test",
                               file_subject="test",
                               data=self.__domain_list_csv)

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
 # parser.add_argument('--region', default="all", dest='region', help='Region to query to a single region default is all regions.')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')

    cmd = parser.parse_args()

    

    start_datetime = datetime.now().replace(tzinfo=pytz.UTC)
    start_datetime_str = str(start_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))
    
    print("Start time is: " + start_datetime_str)
    config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)

    analyze = analyze_audit(config=config, signer=signer, proxy=None)
    analyze.collect_apps()

    end_datetime = datetime.now().replace(tzinfo=pytz.UTC)
    end_datetime_str = str(end_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))



execute_identity_report()