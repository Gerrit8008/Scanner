# instance_manager.py
import os
import yaml
import logging
import subprocess
from client_db import get_client_by_id

def deploy_scanner_instance(client_id):
    """Deploy a scanner instance for a client"""
    try:
        # Get client data
        client = get_client_by_id(client_id)
        
        if not client:
            logging.error(f"Client not found: {client_id}")
            return False
        
        # Create Docker Compose config
        compose_config = {
            'version': '3',
            'services': {
                f'scanner_{client_id}': {
                    'build': {
                        'context': '.',
                        'dockerfile': 'Dockerfile'
                    },
                    'container_name': f'scanner_{client_id}',
                    'volumes': [
                        f'./scanners/client_{client_id}:/app/client_data'
                    ],
                    'environment': [
                        f'CLIENT_ID={client_id}',
                        f'SCANNER_NAME={client["scanner_name"]}',
                        'FLASK_ENV=production'
                    ],
                    'ports': [
                        f'{5000 + int(client_id)}:5000'
                    ],
