import os
import sys
import subprocess
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
import azure.functions as func
import logging
import base64

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        
  
        cluster_endpoint = os.getenv("CLUSTER_ENDPOINT")  # Service Fabric cluster endpoint

      

        # Load the .pfx certificate from a file
        with open("aExampleCertificate.pfx", "rb") as f:
            pfx_certificate_bytes = f.read()
        
        

        # Load the .pfx certificate and extract the private key and certificate
        private_key, certificate, _ = pkcs12.load_key_and_certificates(pfx_certificate_bytes, b"")

        # Serialize the private key and certificate into .pem format
        pem_private_key = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        pem_certificate = certificate.public_bytes(encoding=Encoding.PEM)

        # Define path to the directory where you have write permission
        output_dir = os.path.expanduser("~")  # this will point to the home directory

        # Save the private key and certificate to .pem files in this directory
        pem_path = os.path.join(output_dir, "cluster_connection.pem")
        with open(pem_path, "wb") as f:
            f.write(pem_private_key)
            f.write(pem_certificate)

        # Connect to the Service Fabric cluster
        connect_command = f"sfctl cluster select --endpoint {cluster_endpoint} --pem {pem_path} --no-verify"
        try:
            subprocess.run(connect_command, shell=True, check=True)
            logging.info("Successfully connected to the Service Fabric cluster.")
        except subprocess.CalledProcessError as e:
            logging.exception(f"Failed to connect to the Service Fabric cluster: {e}")
            raise
        
        # Define service name
        service_name = "ExampleApp~exampleServiceName"

        # Fetch the partition ID for the service
        partitions_command = f"sfctl partition list --service-id {service_name}"
        partitions_result = subprocess.check_output(partitions_command, shell=True).decode("utf-8").strip()
        partitions = json.loads(partitions_result)
        partition_id = partitions['items'][0]['partitionInformation']['id']
        
        # Fetch the replica ID for the partition
        replicas_command = f"sfctl replica list --partition-id {partition_id}"
        replicas_result = subprocess.check_output(replicas_command, shell=True).decode("utf-8").strip()
        replicas = json.loads(replicas_result)
        replica_id = replicas['items'][0]['instanceId']
        node_name = replicas['items'][0]['nodeName']

        delete_command = f"sfctl replica remove --partition-id {partition_id} --replica-id {replica_id} --node-name {node_name} --force-remove FORCE_REMOVE"
        try:
            subprocess.run(delete_command, shell=True, check=True)
            logging.info(f"Successfully deleted replica {replica_id} from partition {partition_id}.")
            
        except subprocess.CalledProcessError as e:
            logging.exception(f"Failed to delete replica {replica_id} from partition {partition_id}: {e}")
            raise


        

        return func.HttpResponse(f"Successfully deleted replica {replica_id} from partition {partition_id}.", status_code=200)
    except Exception as e:
        # Log the error details
        logging.exception('An error occurred: {}'.format(e))

        # Return an HTTP 500 error with the error message
        return func.HttpResponse(f"An error occurred: {str(e)}", status_code=500)
