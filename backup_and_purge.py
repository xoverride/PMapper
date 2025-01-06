#!/usr/bin/env python3
import os
import shutil
from datetime import datetime
import subprocess


def backup_and_purge_principalmapper():
    # Define paths - updated for macOS
    principalmapper_dir = os.path.expanduser("~/Library/Application Support/com.nccgroup.principalmapper")
    base_backup_dir = os.path.expanduser("~/Documents/backups/pmapper_backup")

    # Check if principalmapper directory exists
    if not os.path.exists(principalmapper_dir):
        print("PrincipalMapper directory not found at:", principalmapper_dir)
        return False

    # Create timestamp for backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(base_backup_dir, f"pmapper_backup_{timestamp}")

    try:
        # Create backup directory if it doesn't exist
        os.makedirs(base_backup_dir, exist_ok=True)

        # Create backup
        print(f"Creating backup at: {backup_dir}")
        shutil.copytree(principalmapper_dir, backup_dir)

        # Remove all contents of the principalmapper directory
        print("Purging PrincipalMapper data...")
        for item in os.listdir(principalmapper_dir):
            item_path = os.path.join(principalmapper_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                print(f"Error while deleting {item_path}: {e}")

        print("Backup and purge completed successfully!")
        print(f"Backup location: {backup_dir}")
        return True

    except Exception as e:
        print(f"Error during backup/purge: {e}")
        return False


if __name__ == "__main__":
    backup_and_purge_principalmapper()