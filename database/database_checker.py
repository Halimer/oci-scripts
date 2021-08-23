import oci
from oci.database.models import AutonomousDatabase
from oci.config import from_file
import os

config = from_file(file_location="~/.oci/config")


print(config)

compartment_id = config["tenancy"]

identity = oci.database.DatabaseClient(config)
request = AutonomousDatabase()
request.name = "Checking ADB Settings"
request.description = "created by Chad with the OCI Python SDK to check ADB security settings"
settings = identity.list_autonomous_databases(compartment_id)






print(settings.data)


