#!/usr/bin/env python3
"""
Basic tests for NetMon package structure
"""

import pytest
import sys
from pathlib import Path

def test_package_imports():
    """Test that all main modules can be imported"""
    try:
        import netmon
        from netmon import device_info, route_info, neighbor_info, mdb_info, rule_info
        assert netmon.__version__ == "1.0.0"
    except ImportError as e:
        pytest.fail(f"Failed to import netmon modules: {e}")

def test_module_main_functions():
    """Test that all modules have main() functions"""
    from netmon import device_info, route_info, neighbor_info, mdb_info, rule_info
    
    modules = [device_info, route_info, neighbor_info, mdb_info, rule_info]
    
    for module in modules:
        assert hasattr(module, 'main'), f"{module.__name__} missing main() function"
        assert callable(module.main), f"{module.__name__}.main is not callable"

def test_cffi_import():
    """Test that CFFI is available"""
    try:
        from cffi import FFI
        ffi = FFI()
        assert ffi is not None
    except ImportError:
        pytest.fail("CFFI not available - required dependency")

def test_package_metadata():
    """Test package metadata"""
    import netmon
    
    assert hasattr(netmon, '__version__')
    assert hasattr(netmon, '__author__')
    assert hasattr(netmon, '__email__')
    assert hasattr(netmon, '__license__')
    
    assert netmon.__version__ == "1.0.0"
    assert netmon.__author__ == "Harry Coin"
    assert netmon.__license__ == "MIT"

def test_python_version():
    """Test that Python version is 3.8+"""
    assert sys.version_info >= (3, 8), "Python 3.8+ required"

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
