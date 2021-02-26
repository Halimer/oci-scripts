##########################################################################
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
#
# frugal.py
# @author base: Josh Hammer
#
# Supports Python 3 and above
#
# coding: utf-8
##########################################################################

import oci

config = oci.config.from_file()

query = "query instance, autonomousdatabase, database, dbsystem resources"

query = "query instance, autonomousdatabase, database, dbsystem resources where (freeformTags.key = 'Frugal' && freeformTags.value = 'Yes')"

# query = "query all resources where definedTags.key = 'CreatedBy' && definedTags.value = 'oracleidentitycloudservice/tom.liakos@oracle.com'"

#query = "query instance, autonomousdatabase, database, dbsystem resources where definedTags.key = 'CreatedBy' && definedTags.value = 'oracleidentitycloudservice/josh.hammer@oracle.com'"

resource_search_client = oci.resource_search.ResourceSearchClient(config)
def tag_all_resources(config, query, freeform_tags):
    search_resources_response = resource_search_client.search_resources(
        search_details=oci.resource_search.models.StructuredSearchDetails(
            type="Structured", 
            query=query))

    core_client = oci.core.ComputeClient(config)
    database_client = oci.database.DatabaseClient(config)

    print("Display Name, Resource Type, OCID, Compartment ID")
    for item in search_resources_response.data.items:
        if item.resource_type == "Instance":
            update_instance_response = core_client.update_instance(instance_id=item.identifier,
            update_instance_details=oci.core.models.UpdateInstanceDetails(freeform_tags={'Frugal': 'Yes','Stopped': '20201224'}))

        elif item.resource_type == "Database":
            update_database_response = database_client.update_database(database_id=item.identifier,
            update_database_details=oci.database.models.UpdateDatabaseDetails(freeform_tags={'Frugal': 'Yes','Stopped': '20201224'}))
        
        elif item.resource_type == "DbSystem":
            update_db_system_response = database_client.update_db_system(db_system_id=item.identifier,
            update_db_system_details=oci.database.models.UpdateDbSystemDetails(freeform_tags={'Frugal': 'Yes','Stopped': '20201224'}))

        elif item.resource_type == "AutonomousDatabase":
            update_autonomous_database_response = database_client.update_autonomous_database(autonomous_database_id=item.identifier,
            update_autonomous_database_details=oci.database.models.UpdateAutonomousDatabaseDetails(freeform_tags={'Frugal': 'Yes','Stopped': '20201224'}))
        
        print(item.display_name + "," + item.resource_type + "," + item.identifier + "," + item.compartment_id)

#############################################################
# Stops an Instance based on instance ID
#############################################################
def stop_instance(core_client, instance_id):
    print("Stopping Instance: ", instance_id)
    try:
        response = core_client.instance_action(instance_id=instance_id, action="STOP")
    except Exception as e:
            raise RuntimeError("Error in stop_instance " + str(e.args))


#############################################################
# Stops an Autonmous Database based on instance ID
#############################################################
def stop_autonomous(database_client, autonomous_database_id):
    print("Stopping Autonomous Database: ", autonomous_database_id)
    try:
        response = database_client.autonomous_database_id(autonomous_database_id=autonomous_database_id)
    except Exception as e:
            raise RuntimeError("Error in stop_instance " + str(e.args))

def stop_database_node(database_client, compartment_id, db_system_id):
    print("Stopping Autonomous Database: ", db_system_id)
    try:
        db_nodes = oci.pagination.list_call_get_all_results(
            database_client.list_db_nodes,
            compartment_id,
            db_system_id=db_system_id).data
        
        response = database_client.autonomous_database_id(autonomous_database_id=autonomous_database_id)
    except Exception as e:
            raise RuntimeError("Error in stop_instance " + str(e.args))





#############################################################
# Stops an Autonmous Database based on instance ID
#############################################################
def get_database_ip(signer, compartment_id, db_system_id):
    db_private_ips = []

    db_client = oci.database.DatabaseClient(config={}, signer=signer)
    db_nodes = oci.pagination.list_call_get_all_results(
            db_client.list_db_nodes,
            compartment_id,
            db_system_id=db_system_id).data
    for db_node in db_nodes:
        # Adding DB Nodes VNICs to find IPs
        vnic_ips = get_vnic_private_ips(signer, db_node.vnic_id)