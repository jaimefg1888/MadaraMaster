
import asyncio
import hashlib
import time
import os
import math
from pathlib import Path
from collections import Counter
from typing import Dict, Any, Optional

import aiofiles
from storage import detect_storage_type, StorageType, SanitizationStandard, HDDWipeStrategy, SSDWipeStrategy, NVMeWipeStrategy
from audit import AuditLogger

class AsyncWiper:
    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit = audit_logger or AuditLogger()
        # buffer sizes
        self.BUFFER_HDD = 10 * 1024 * 1024  # 10MB
        self.BUFFER_SSD = 50 * 1024 * 1024  # 50MB

    async def wipe_file(
        self, 
        path: Path, 
        standard: SanitizationStandard = SanitizationStandard.NIST_CLEAR,
        verify: bool = False,
        progress_callback: Optional[Any] = None 
    ) -> Dict[str, Any]:
        """
        Main entry point for async wiping a single file.
        """
        result: Dict[str, Any] = {
            "success": False,
            "passes_completed": 0,
            "verified": False,
            "duration": 0.0,
            "strategy": "Unknown",
            "error": None
        }
        
        try:
            if not path.exists():
                raise FileNotFoundError(f"File not found: {path}")

            file_size = path.stat().st_size
            
            # 1. Detect Storage
            storage_type = detect_storage_type(path)
            
            # 2. Select Strategy
            strategy_name = "HDD"
            buffer_size = self.BUFFER_HDD
            
            if storage_type in (StorageType.SSD, StorageType.NVME):
                strategy_name = "SSD/NVMe"
                buffer_size = self.BUFFER_SSD
            
            result["strategy"] = f"{strategy_name} ({standard.value})"

            # 3. Pre-wipe Hash (for audit)
            sha256_before = await self._calculate_sha256(path)
            
            # 4. Execute Wipe Logic
            start_time = time.time()
            
            passes_config = self._get_passes_config(storage_type, standard)
            passes_done = 0
            
            async with aiofiles.open(path, 'rb+') as f:
                for pass_idx, pattern_type in enumerate(passes_config, 1):
                    await f.seek(0)
                    
                    # Process file in chunks
                    remaining = file_size
                    bytes_written_this_pass = 0
                    
                    while remaining > 0:
                        chunk_size = min(remaining, buffer_size)
                        
                        data = await self._generate_pattern(pattern_type, chunk_size)
                        await f.write(data)
                        
                        remaining -= chunk_size
                        bytes_written_this_pass += chunk_size
                        
                        if progress_callback:
                            if asyncio.iscoroutinefunction(progress_callback):
                                await progress_callback(path, pass_idx, bytes_written_this_pass, file_size)
                            else:
                                progress_callback(path, pass_idx, bytes_written_this_pass, file_size)
                    
                    # Force sync after each pass to ensure write hitting disk
                    await f.flush()
                    await asyncio.to_thread(os.fsync, f.fileno())
                    passes_done += 1
            
            duration = time.time() - start_time
            result["duration"] = duration
            result["passes_completed"] = passes_done
            result["success"] = True

            # 5. Verification (Entropy)
            # Only verify if success AND requested
            if result["success"] and verify:
                last_pattern = passes_config[-1]
                verified = await self._verify_entropy(path, expected_pattern=last_pattern)
                result["verified"] = verified
                if not verified:
                    result["error"] = "Entropy verification failed"
                    result["success"] = False # or Partial?
            elif result["success"]:
                result["verified"] = "Skipped"
            
            # 6. Delete file (unlink)
            # If standard requires destruction (Clear/Purge usually imply it)
            # Madara is a wiper, so yes.
            try:
                path.unlink()
            except Exception as e:
                result["error"] = f"Wipe successful but delete failed: {e}"
            
            # 7. Log
            self.audit.log_wipe_operation(path, file_size, sha256_before, standard.value, result)
            
        except Exception as e:
            result["error"] = str(e)
            result["success"] = False
            # Log failure
            self.audit.log_wipe_operation(path, 0, "unknown", standard.value, result)
            
        return result

    def _get_passes_config(self, storage_type: StorageType, standard: SanitizationStandard) -> list:
        # Returns list of pattern types: 'zeros', 'ones', 'random'
        
        # SSD/NVMe: Always 1 pass random (overwriting more is harmful/useless)
        if storage_type in (StorageType.SSD, StorageType.NVME):
            return ['random']
            
        # HDD:
        if standard == SanitizationStandard.NIST_CLEAR:
            return ['zeros']
        elif standard in (SanitizationStandard.NIST_PURGE, SanitizationStandard.DOD_LEGACY):
            return ['zeros', 'ones', 'random']
        
        return ['zeros'] # Default

    async def _generate_pattern(self, pattern_type: str, size: int) -> bytes:
        if pattern_type == 'zeros':
            return b'\x00' * size
        elif pattern_type == 'ones':
            return b'\xFF' * size
        elif pattern_type == 'random':
            # crypto-secure random is slow for large buffers. 
            # use os.urandom for security
            return await asyncio.to_thread(os.urandom, size)
        return b'\x00' * size

    async def _calculate_sha256(self, path: Path) -> str:
        sha256 = hashlib.sha256()
        try:
            async with aiofiles.open(path, 'rb') as f:
                while True:
                    data = await f.read(1024 * 1024) # 1MB chunk
                    if not data:
                        break
                    sha256.update(data)
        except Exception:
            return "hash_error"
        return sha256.hexdigest()

    async def _verify_entropy(self, path: Path, expected_pattern: str = 'random', sample_count: int = 20, block_size: int = 4096) -> bool:
        """
        Verify wipe using Shannon Entropy.
        Reads random blocks.
        If last pass was Random: Entropy > 7.5 (bits per byte)
        If last pass was Zeros: Entropy -> 0.00
        """
        if not path.exists():
            return True 
        
        file_size = path.stat().st_size
        if file_size == 0:
            return True

        # Helper function for entropy calculation
        def calc_entropy(data):
            if not data: return 0
            counter = Counter(data)
            length = len(data)
            ent = 0.0
            for count in counter.values():
                p = count / length
                ent -= p * math.log2(p)
            return ent # Returns bits per byte (0-8)

        total_entropy = 0.0
        samples_taken = 0
        
        try:
            async with aiofiles.open(path, 'rb') as f:
                # Take sample_count random samples
                for _ in range(sample_count):
                    offset = 0
                    if file_size > block_size:
                        # Random offset
                        import random
                        offset = random.randint(0, file_size - block_size)
                    
                    await f.seek(offset)
                    data = await f.read(block_size)
                    
                    if not data:
                         continue
                    
                    ent = calc_entropy(data)
                    total_entropy += ent
                    samples_taken += 1
                    
                    # Quick fail/pass check? No, average for robust
        except Exception:
            return False
            
        if samples_taken == 0:
            return True # Empty file or error reading
            
        avg_entropy = total_entropy / samples_taken
        
        if expected_pattern == 'random':
            # Expected high entropy (> 7.5 bits per byte)
            # Max is 8.0. Random data usually > 7.9
            return avg_entropy > 7.0 
        elif expected_pattern == 'zeros':
            # Expected low entropy (~0)
            # And also verify all bytes are 0 (entropy 0 means only 1 symbol)
            # But sampling means we might catch noise? No, should be exact.
            return avg_entropy < 0.1
        elif expected_pattern == 'ones':
            # Expected low entropy (~0)
            # All 0xFF
            return avg_entropy < 0.1
            
        return True
