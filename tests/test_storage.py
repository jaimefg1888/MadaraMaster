
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from storage import detect_storage_type, StorageType

# Mock the platform system
@pytest.fixture
def mock_system(request):
    with patch("platform.system", return_value=request.param):
        yield

# --- Linux Tests ---
@pytest.mark.parametrize("mock_system", ["Linux"], indirect=True)
def test_linux_ssd_detection(mock_system):
    with patch("subprocess.check_output") as mock_run, \
         patch("pathlib.Path.read_text") as mock_read, \
         patch("pathlib.Path.exists", return_value=True):
        
        # Mock df output
        mock_run.return_value = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 10 90 10% /"
        # Mock rotational = 0 (SSD)
        mock_read.return_value = "0"
        
        assert detect_storage_type(Path("/tmp/foo")) == StorageType.SSD

@pytest.mark.parametrize("mock_system", ["Linux"], indirect=True)
def test_linux_hdd_detection(mock_system):
    with patch("subprocess.check_output") as mock_run, \
         patch("pathlib.Path.read_text") as mock_read, \
         patch("pathlib.Path.exists", return_value=True):
        
        mock_run.return_value = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 10 90 10% /"
        # Mock rotational = 1 (HDD)
        mock_read.return_value = "1"
        
        assert detect_storage_type(Path("/tmp/foo")) == StorageType.HDD

# --- Windows Tests ---
@pytest.mark.parametrize("mock_system", ["Windows"], indirect=True)
def test_windows_ssd_detection(mock_system):
    with patch("subprocess.check_output") as mock_run:
        # Mock PowerShell outputs
        # First call: MediaType
        mock_run.side_effect = ["SSD", "Samsung SSD 860 EVO"] 
        
        assert detect_storage_type(Path("C:\\foo.txt")) == StorageType.SSD

@pytest.mark.parametrize("mock_system", ["Windows"], indirect=True)
def test_windows_nvme_detection(mock_system):
    with patch("subprocess.check_output") as mock_run:
        # First call: MediaType=SSD, Second call: Model contains NVMe
        mock_run.side_effect = ["SSD", "Samsung SSD 970 EVO Plus NVMe M.2"]
        
        assert detect_storage_type(Path("C:\\foo.txt")) == StorageType.NVME

# --- macOS Tests ---
@pytest.mark.parametrize("mock_system", ["Darwin"], indirect=True)
def test_macos_ssd_detection(mock_system):
    with patch("subprocess.check_output") as mock_run:
        mock_run.return_value = "   Device Identifier:        disk1s1\n   Solid State:              Yes\n   Protocol:                 SATA"
        
        assert detect_storage_type(Path("/Users/foo")) == StorageType.SSD
