#!/usr/bin/python3
############## Directions for non cloud-shell use ##########################
# To use the script locally copy the contents of this file to identity-audit-tool.py
# To run on a local machine with `python3 identity-audit-tool.py -l`
# To run on a local machine with a different oci profile `python3 identity-audit-tool.py -t <profile_name>`
# To run on a machine with instance principal `python3 identity-audit-tool.py -ip`
##########################################################################

from fileinput import filename
import os, oci, dateutil, datetime, argparse
 
# Credentials created before this date need to be rotated
EPOCH = dateutil.parser.parse('2022-01-19T18:45:00.000+00:00')

##########################################################################
# Runs the identity report
##########################################################################
def execute_identity_report():

    # Get Command Line Parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', default="", dest='config_profile', help='Config file section to use (tenancy profile)')
    parser.add_argument('-l', action='store_true', default=False, dest='is_local_config', help='Use on local machine with an ~/.oci/config file.')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=True, dest='is_delegation_token', help='Use Delegation Token for Authentication')

    cmd = parser.parse_args()


    # If any flags other than dt then is_delegation_token = false
    if cmd.is_local_config or cmd.is_instance_principals or cmd.config_profile != "":
        cmd.is_delegation_token = False
    config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)
    identity_audit_tool(config,signer, cmd.is_delegation_token)

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

def identity_audit_tool(config, signer, cloudshell):

    retryable_codes = {-1: [], 404: [], 429: []}
    retry_strategy = oci.retry.RetryStrategyBuilder().add_service_error_check(service_error_retry_config = retryable_codes).get_retry_strategy()
    identity_client = oci.identity.IdentityClient(config, signer = signer, retry = oci.retry.DEFAULT_RETRY_STRATEGY)
    num_credentials_to_be_rotated = 0
    
    try:
        tenancy_data = identity_client.get_tenancy(config["tenancy"]).data
        tenancy_id = tenancy_data.id
        if cloudshell:
            file_name = "audit.csv"
        else:
            file_name = tenancy_data.name + "-audit.csv"
    except Exception as e:
        print("Failed to get tenancy ID: " + str(e))

    try:
        with open(file_name, 'w') as fd:
            fd.write('Credential ID,Credential Type,Credential Status,User Name,User OCID,Created Date\n')
    
            for user in oci.pagination.list_call_get_all_results_generator(identity_client.list_users, 'record', tenancy_id):
                if user.identity_provider_id is None:
                    uipassword = identity_client.get_user_ui_password_information(user.id).data
    
                    if uipassword.time_created < EPOCH:
                        num_credentials_to_be_rotated += 1
                        print(f"Console UI password of user '{user.name}' needs to be rotated")
                        fd.write(f'UI password,UI password,ACTIVE,{user.name},{user.id},{uipassword.time_created}\n')
    
                for smtp_credential in identity_client.list_smtp_credentials(user.id).data:
                    if smtp_credential.time_created < EPOCH:
                        num_credentials_to_be_rotated += 1
                        print(f"SMTP Credential '{smtp_credential.id}' of user '{user.name}' needs to be rotated")
                        fd.write(f'{smtp_credential.id},SMTP Credential,{smtp_credential.lifecycle_state},{user.name},{user.id},{smtp_credential.time_created}\n')
    
                for auth_token in identity_client.list_auth_tokens(user.id).data:
                    if auth_token.time_created < EPOCH:
                        num_credentials_to_be_rotated += 1
                        print(f"AUTH Token '{auth_token.id}' of user '{user.name}' needs to be rotated")
                        fd.write(f'{auth_token.id},AUTH Token,{auth_token.lifecycle_state},{user.name},{user.id},{auth_token.time_created}\n')
    
                for oauth2_client_credential in identity_client.list_o_auth_client_credentials(user.id).data:
                    if oauth2_client_credential.time_created < EPOCH:
                        num_credentials_to_be_rotated += 1
                        print(f"OAUTH 2.0 Client Credential '{oauth2_client_credential.id}' of user '{user.name}' needs to be rotated")
                        fd.write(f'{oauth2_client_credential.id},OAUTH 2.0 Client Credential,{oauth2_client_credential.lifecycle_state},{user.name},{user.id},{oauth2_client_credential.time_created}\n')
    
                for totp_device in identity_client.list_mfa_totp_devices(user.id).data:
                    if totp_device.time_created < EPOCH:
                        totp_device_status = '' if totp_device.is_activated else 'INACTIVE '
                        num_credentials_to_be_rotated += 1
                        print(f"{totp_device_status}MFA TOTP Device '{totp_device.id}' of user '{user.name}' needs to be rotated")
                        fd.write(f'{totp_device.id},MFA TOTP Device,{totp_device_status},{user.name},{user.id},{totp_device.time_created}\n')
    
                for customer_secret_key in identity_client.list_customer_secret_keys(user.id).data:
                    if customer_secret_key.time_created < EPOCH:
                        num_credentials_to_be_rotated += 1
                        print(f"Customer Secret Key '{customer_secret_key.id}' of user '{user.name}' needs to be rotated")
                        fd.write(f'{customer_secret_key.id},Customer Secret Key,{customer_secret_key.lifecycle_state},{user.name},{user.id},{customer_secret_key.time_created}\n')
    
            for idp in identity_client.list_identity_providers('SAML2', tenancy_id).data:
                if idp.freeform_attributes is not None and 'scimClientSecretCreatedOn' in idp.freeform_attributes:
                    scim_client_secret_created_on = datetime.datetime.fromtimestamp(
                        int(idp.freeform_attributes['scimClientSecretCreatedOn']) // 1000
                    ).replace(tzinfo = dateutil.tz.tzutc())
                else:
                    scim_client_secret_created_on = idp.time_created
    
                if scim_client_secret_created_on < EPOCH:
                    num_credentials_to_be_rotated += 1
                    print(f"IdP Client Credential of Identity Provider '{idp.id}' needs to be rotated")
                    fd.write(f'{idp.id},IDP Client Credential,ACTIVE,{idp.name},{idp.id},{scim_client_secret_created_on}\n')
    
            if num_credentials_to_be_rotated == 0:
                print("Found no affected credential")
            else:
                print(f"Number of credentials to be rotated: {num_credentials_to_be_rotated}")
                print("Audit report was written to file '" + file_name + "'")
    except Exception as exp:
        print(f"Error: {exp}")

execute_identity_report()