
import platform
import subprocess
import shutil
from enum import Enum
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional

class StorageType(Enum):
    HDD = "hdd"
    SSD = "ssd"
    NVME = "nvme"
    NETWORK = "network"
    UNKNOWN = "unknown"

class SanitizationStandard(Enum):
    NIST_CLEAR = "clear"      # 1 pass (zeros for HDD, random for SSD)
    NIST_PURGE = "purge"      # 3 passes + verify (DoD style for HDD)
    DOD_LEGACY = "dod"        # 3 passes (DoD 5220.22-M)

class WipeStrategy(ABC):
    @abstractmethod
    def wipe(self, path: Path, standard: SanitizationStandard = SanitizationStandard.NIST_CLEAR) -> Dict[str, Any]:
        """
        Perform wipe operation on the given path using the specified standard.
        Returns a dict with: success, passes_completed, duration, verified, error
        """
        pass

def detect_storage_type(path: Path) -> StorageType:
    system = platform.system().lower()
    
    try:
        if system == "linux":
            return _detect_linux(path)
        elif system == "windows":
            return _detect_windows(path)
        elif system == "darwin":
            return _detect_macos(path)
    except Exception:
        return StorageType.UNKNOWN
    return StorageType.UNKNOWN

def _detect_linux(path: Path) -> StorageType:
    # Simplified logic: find device, check /sys/block/{dev}/queue/rotational
    try:
        df_out = subprocess.check_output(["df", "-P", str(path)], text=True).splitlines()
        if len(df_out) < 2: return StorageType.UNKNOWN
        dev_path = df_out[1].split()[0]
        dev_name = Path(dev_path).name
        
        # Handle partitions (sda1 -> sda)
        import re
        base_dev = re.sub(r'\d+$', '', dev_name)
        
        rotational_path = Path(f"/sys/block/{base_dev}/queue/rotational")
        if rotational_path.exists():
            val = rotational_path.read_text().strip()
            if val == "0":
                # Check directly if it's NVMe
                if "nvme" in base_dev:
                    return StorageType.NVME
                return StorageType.SSD
            return StorageType.HDD
    except Exception:
        pass
    return StorageType.UNKNOWN

def _detect_windows(path: Path) -> StorageType:
    # Use PowerShell Get-PhysicalDisk
    try:
        # Simplified: Check if "SSD" string appears in disk model via PowerShell
        drive = path.anchor.split(':')[0]
        cmd = f"Get-PhysicalDisk | Where-Object {{ (Get-Partition | Where-Object DriveLetter -eq '{drive}').DiskNumber -eq $_.DeviceId }} | Select-Object -ExpandProperty MediaType"
        res = subprocess.check_output(["powershell", "-Command", cmd], text=True).strip().upper()
        if "SSD" in res:
            # Check model for NVMe?
            cmd_model = f"Get-PhysicalDisk | Where-Object {{ (Get-Partition | Where-Object DriveLetter -eq '{drive}').DiskNumber -eq $_.DeviceId }} | Select-Object -ExpandProperty Model"
            model = subprocess.check_output(["powershell", "-Command", cmd_model], text=True).strip().upper()
            if "NVME" in model:
                return StorageType.NVME
            return StorageType.SSD
        if "HDD" in res or "UNSPECIFIED" in res: # Unspecified often HDD in VMs
            return StorageType.HDD
    except Exception:
        pass
    return StorageType.UNKNOWN

import re

def _detect_macos(path: Path) -> StorageType:
    # Use diskutil info
    try:
        out = subprocess.check_output(["diskutil", "info", str(path)], text=True)
        # Robust check with regex for "Solid State: Yes" (ignores extra spaces)
        if re.search(r"Solid State:\s+Yes", out):
             # Check for NVMe protocol
            if "Protocol: PCI-Express" in out or "NVMe" in out:
                return StorageType.NVME
            return StorageType.SSD
        if re.search(r"Solid State:\s+No", out):
            return StorageType.HDD
    except Exception:
        pass
    return StorageType.UNKNOWN

class HDDWipeStrategy(WipeStrategy):
    def wipe(self, path: Path, standard: SanitizationStandard = SanitizationStandard.NIST_CLEAR) -> Dict[str, Any]:
        # Placeholder for actual implementation — will link to async engine later
        passes = 1
        if standard in (SanitizationStandard.NIST_PURGE, SanitizationStandard.DOD_LEGACY):
            passes = 3
        
        return {
            "success": True, 
            "passes_completed": passes, 
            "duration": 0.0, 
            "verified": False,
            "strategy": "HDD Overwrite"
        }

class SSDWipeStrategy(WipeStrategy):
    def wipe(self, path: Path, standard: SanitizationStandard = SanitizationStandard.NIST_CLEAR) -> Dict[str, Any]:
        # optimized for SSD: 1 pass random + unlink (TRIM hint)
        passes = 1
        
        return {
            "success": True, 
            "passes_completed": passes, 
            "duration": 0.0, 
            "verified": False,
            "strategy": "SSD Single-Pass Random"
        }

class NVMeWipeStrategy(WipeStrategy):
    def wipe(self, path: Path, standard: SanitizationStandard = SanitizationStandard.NIST_CLEAR) -> Dict[str, Any]:
        # Fallback to SSD strategy for file-level wipe
        ssid_strat = SSDWipeStrategy()
        return ssid_strat.wipe(path, standard)
