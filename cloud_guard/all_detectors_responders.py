
from __future__ import print_function
import argparse
import oci
import datetime
import csv
import os


##########################################################################
# Print to CSV 
##########################################################################
def print_to_csv_file(file_subject, data):
    try:
        # if no data
        if len(data) == 0:
            return

        # get the file name of the CSV
        file_name = file_subject + ".csv"
        
        # add start_date to each dictionary
        now = datetime.datetime.now()
        result = [dict(item, extract_date=now.strftime("%Y-%m-%d %H:%M:%S")) for item in data]

        # generate fields
        fields = [key for key in data[0].keys()]

        with open(file_name, mode='w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fields)

            # write header
            writer.writeheader()

            for row in data:
                writer.writerow(row)

        print("CSV: " + file_subject.ljust(22) + " --> " + file_name)

    except Exception as e:
        raise Exception("Error in print_to_csv_file: " + str(e.args))

##########################################################################
# Arg Parsing function to be updated 
##########################################################################
def set_parser_arguments():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i',
        type=argparse.FileType('r'),
        dest='input',
        help="Input JSON File"
        )
    parser.add_argument(
        '-o',
        type=argparse.FileType('w'),
        dest='output_csv',
        help="CSV Output prefix")
    result = parser.parse_args()

    if len(sys.argv) < 3:
        parser.print_help()
        return None

    return result

##########################################################################
# execute_report
##########################################################################
def execute_report():

    # Get Command Line Parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', default="", dest='config_profile', help='Config file section to use (tenancy profile)')
    parser.add_argument('-p', default="", dest='proxy', help='Set Proxy (i.e. www-proxy-server.com:80) ')
    #parser.add_argument('--output-to-bucket', default="", dest='output_bucket', help='Set Output bucket name (i.e. my-reporting-bucket) ')

    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')
    cmd = parser.parse_args()
    # Getting  Command line  arguments
    # cmd = set_parser_arguments()
    # if cmd is None:
    #     pass
    #     # return

    # Identity extract compartments
    config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)
    cg = Cloud_Guard_Data(config, signer, cmd.proxy)
    
    cg.get_responders()
    cg.get_detectors()
    cg.get_problems()
    cg.get_recommendations()




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


class Cloud_Guard_Data: 
    __compartments = []
    __problems = []
    __detectors = []
    __responders = []
    __recommendations = []

    def __init__(self, config, signer, proxy):
        # Start print time info
        print("Written by Josh Hammer February 2021.  Hacked and botched by Chad Russell")
        print("\n")
        print("Cloud Guard Data")
        self.__config = config
        self.__signer = signer
        # self.__output_bucket = output_bucket
        try:
            self.__identity = oci.identity.IdentityClient(self.__config, signer=self.__signer)
            if proxy:
                self.__identity.base_client.session.proxies = {'https': proxy}
            
            self.__cloud_guard = oci.cloud_guard.CloudGuardClient(self.__config, signer=self.__signer)
            if proxy:
                self.__cloud_guard.base_client.session.proxies = {'https': proxy}

            # Getting Tenancy Data and Region data
            self.__tenancy = self.__identity.get_tenancy(config["tenancy"]).data
            print(self.__tenancy)
            self.__regions = self.__identity.list_region_subscriptions(self.__tenancy.id).data

        except Exception as e:
                raise RuntimeError("Failed to create service objects" + str(e.args))

    def get_detectors(self):
        try: 
            raw_detectors = oci.pagination.list_call_get_all_results(
                self.__cloud_guard.list_detectors,
                compartment_id=self.__tenancy.id
                    ).data

            for detector in raw_detectors:
                detector_rules_raw = oci.pagination.list_call_get_all_results(
                    self.__cloud_guard.list_detector_rules,
                    detector_id=detector.id,
                    compartment_id=self.__tenancy.id
                ).data
                
                for rule in detector_rules_raw:
                    cg_rule = {
                        "display_name" : rule.display_name,
                        "id" : rule.id,
                        "description" : rule.description,
                        "risk_level" : rule.detector_details.risk_level,
                        "recommendation" : rule.recommendation,
                        "resource_type" : rule.resource_type,
                        "service_type" : rule.service_type,
                        "detector" : rule.detector,
                        "detector_labels" : str(rule.detector_details.labels),
                        "candidate_responder_rules" : str(rule.candidate_responder_rules).replace('\n',''),
                        "managed_list_types" : str(rule.managed_list_types),
                        "lifecycle_details" : rule.lifecycle_details,
                        "lifecycle_state" : rule.lifecycle_state,
                        "time_created" : str(rule.time_created),
                        "time_update" : str(rule.time_updated)
                    }
                    self.__detectors.append(cg_rule)
            print_to_csv_file('all_detectors', self.__detectors)
        except Exception as e:
            raise RuntimeError("Failed to get responders" + str(e.args))
        
    def get_responders(self):
            try: 
                raw_responders = oci.pagination.list_call_get_all_results(
                    self.__cloud_guard.list_responder_rules,
                    compartment_id=self.__tenancy.id
                        ).data                    
                for rule in raw_responders:
                    cg_rule = {
                        "display_name" : rule.display_name,
                        "id" : rule.id,
                        "description" : rule.description,
                        "type" : rule.type,
                        "is_enabled" : str(rule.details.is_enabled),
                        "mode" : rule.details.mode,
                        "condition" : rule.details.condition,
                        "configurations" : str(rule.details.configurations).replace('\n',''),
                        "lifecycle_details" : rule.lifecycle_details,
                        "lifecycle_state" : rule.lifecycle_state,
                        "policies" : str(rule.policies).replace('\n',''),
                        "supported_modes" : rule.supported_modes,
                        "time_created" : str(rule.time_created),
                        "time_update" : str(rule.time_updated)
                    }
                    self.__responders.append(cg_rule)
                print_to_csv_file('all_responders', self.__responders)
            except Exception as e:
                raise RuntimeError("Failed to get detectors" + str(e.args))
    
    def get_recommendations(self):
            try: 
                raw_recommendations = oci.pagination.list_call_get_all_results(
                    self.__cloud_guard.list_recommendations,   
                    compartment_id=self.__tenancy.id
                        ).data                    
                for recommendations in raw_recommendations:
                    cg_recommendations = {
                        "name" : recommendations.name,
                        "id" : recommendations.id,
                        "description" : recommendations.description,
                        "time_created" : str(recommendations.time_created),
                        "time_update" : str(recommendations.time_updated)
                    }
                    self.__recommendations.append(cg_recommendations)
                print_to_csv_file('all_recommendations', self.__recommendations)
            except Exception as e:
                raise RuntimeError("Failed to get recommendations" + str(e.args))



    def get_problems(self):
        try: 
            # Getting all compartments in tenancy
            compartments = oci.pagination.list_call_get_all_results(
                self.__identity.list_compartments,
                self.__tenancy.id
            ).data

            # Adding the tenancy to the list of compartments
            compartments.append(self.__tenancy)
        except Exception as e:
            raise RuntimeError("Failed to get compartments " + str(e.args))    
        
        try:
            for compartment in compartments: 
                raw_problems = oci.pagination.list_call_get_all_results(
                    self.__cloud_guard.list_problems,
                    compartment.id
                        ).data
                
                for problem in raw_problems:
                    problem = {
                        "id" : problem.id,
                        "compartment_id" : problem.compartment_id,
                        "detector_rule_id" : problem.detector_rule_id,
                        "risk_level" : problem.risk_level,
                        "resource_name" : problem.resource_name,
                        "resource_id" : problem.resource_id,
                        "resource_type" : problem.resource_type,
                        "time_first_detected" : problem.time_first_detected,
                        "time_last_detected" : problem.time_last_detected,
                        "labels" : str(problem.labels).replace('\n',''),
                        "lifecycle_detail" : problem.lifecycle_detail,
                        "lifecycle_state" : problem.lifecycle_state,
                        "region" : problem.region,
                        "target_id" : problem.target_id,
                        "detector_id" : problem.detector_id
                        
                    }
                    self.__problems.append(problem)
            
            print_to_csv_file("all_problems", self.__problems)
        except Exception as e:
            raise RuntimeError("Failed to get problems " + str(e.args))    


##########################################################################
# Main
##########################################################################

execute_report()
