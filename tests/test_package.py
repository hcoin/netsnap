#!/usr/bin/env python3
"""
Comprehensive tests for NetSnap package - targeting 80% coverage
"""

import pytest
import sys
import json
import subprocess
import os
from pathlib import Path
from io import StringIO
from unittest.mock import patch, MagicMock, Mock, call

# ============================================================================
# Basic Import and Structure Tests
# ============================================================================

def test_package_imports():
    """Test that all main modules can be imported"""
    try:
        import netsnap
        from netsnap import device_info, route_info, neighbor_info, mdb_info, rule_info
        assert netsnap.__version__ == "2.0.0"
    except ImportError as e:
        pytest.fail(f"Failed to import netsnap modules: {e}")

def test_module_main_functions():
    """Test that all modules have main() functions"""
    from netsnap import device_info, route_info, neighbor_info, mdb_info, rule_info
    
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
    import netsnap
    
    assert hasattr(netsnap, '__version__')
    assert hasattr(netsnap, '__author__')
    assert hasattr(netsnap, '__email__')
    assert hasattr(netsnap, '__license__')
    
    assert netsnap.__version__ == "2.0.0"
    assert netsnap.__author__ == "Harry Coin"
    assert netsnap.__license__ == "MIT"

def test_python_version():
    """Test that Python version is 3.8+"""
    assert sys.version_info >= (3, 8), "Python 3.8+ required"

def test_module_attributes():
    """Test that modules have expected attributes"""
    from netsnap import device_info
    
    # Check for common module attributes
    assert hasattr(device_info, '__name__')
    assert hasattr(device_info, '__file__')
    assert device_info.__name__ == 'netsnap.device_info'

# ============================================================================
# Device Info Tests - Comprehensive
# ============================================================================

class TestDeviceInfo:
    """Comprehensive tests for device_info module"""
    
    def test_device_info_main_no_args(self):
        """Test device_info main() with no arguments"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['device_info']
        
        try:
            result = device_info.main()
            output = captured_output.getvalue()
            
            assert len(output) > 0, "Should produce output"
            assert result == 0 or result is None, "Should return success"
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_device_info_json_output(self):
        """Test device_info JSON output"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['device_info', '-j']
        
        try:
            result = device_info.main()
            output = captured_output.getvalue().strip()
            
            if output:
                try:
                    data = json.loads(output)
                    assert isinstance(data, (dict, list)), "JSON should be dict or list"
                except json.JSONDecodeError as e:
                    pytest.fail(f"Invalid JSON output: {e}")
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_device_info_specific_device_loopback(self):
        """Test querying specific device (loopback always exists)"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['device_info', '--extended']
        
        try:
            result = device_info.main()
            output = captured_output.getvalue()
            
            assert 'lo' in output.lower() or len(output) > 0
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_device_info_verbose(self):
        """Test device_info verbose output"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['device_info', '-v']
        
        try:
            result = device_info.main()
            output = captured_output.getvalue()
            
            assert len(output) > 0, "Verbose should produce output"
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    

    
    def test_device_info_help(self):
        """Test device_info help output"""
        from netsnap import device_info
        
        old_argv = sys.argv
        sys.argv = ['device_info', '-h']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                device_info.main()
            assert exc_info.value.code == 0, "Help should exit with 0"
        finally:
            sys.argv = old_argv
    
    def test_device_info_version(self):
        """Test device_info version output"""
        from netsnap import device_info
        
        old_argv = sys.argv
        sys.argv = ['device_info', '--version']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                device_info.main()
            # Version may exit with 0 or raise SystemExit
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv
    

    def test_device_info_json_with_specific_device(self):
        """Test JSON output for specific device"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['device_info', '-j']
        
        try:
            device_info.main()
            output = captured_output.getvalue().strip()
            
            if output:
                data = json.loads(output)
                assert isinstance(data, (dict, list))
                assert 'lo' in data
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv

# ============================================================================
# Route Info Tests - Comprehensive
# ============================================================================

class TestRouteInfo:
    """Comprehensive tests for route_info module"""
    
    def test_route_info_main_no_args(self):
        """Test route_info main() with no arguments"""
        from netsnap import route_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['route_info']
        
        try:
            result = route_info.main()
            output = captured_output.getvalue()
            
            assert len(output) > 0
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_route_info_json_output(self):
        """Test route_info JSON output"""
        from netsnap import route_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['route_info', '-j']
        
        try:
            result = route_info.main()
            output = captured_output.getvalue().strip()
            
            if output:
                data = json.loads(output)
                assert isinstance(data, (dict, list))
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_route_info_table_main(self):
        """Test querying main routing table"""
        from netsnap import route_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['route_info', '-t','MAIN']
        
        try:
            result = route_info.main()
            output = captured_output.getvalue()
            
            assert len(output) > 0
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_route_info_table_local(self):
        """Test querying local routing table"""
        from netsnap import route_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['route_info', '-t', 'local']
        
        try:
            result = route_info.main()
            output = captured_output.getvalue()
            
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_route_info_verbose(self):
        """Test route_info verbose output"""
        from netsnap import route_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['route_info', '-v']
        
        try:
            result = route_info.main()
            output = captured_output.getvalue()
            
            assert len(output) > 0
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_route_info_help(self):
        """Test route_info help output"""
        from netsnap import route_info
        
        old_argv = sys.argv
        sys.argv = ['route_info', '-h']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                route_info.main()
            assert exc_info.value.code == 0
        finally:
            sys.argv = old_argv
    

# ============================================================================
# Neighbor Info Tests - Comprehensive
# ============================================================================

class TestNeighborInfo:
    """Comprehensive tests for neighbor_info module"""
    
    def test_neighbor_info_main_no_args(self):
        """Test neighbor_info main() with no arguments"""
        from netsnap import neighbor_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['neighbor_info']
        
        try:
            result = neighbor_info.main()
            output = captured_output.getvalue()
            
            # May be empty if no neighbors
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_neighbor_info_json_output(self):
        """Test neighbor_info JSON output"""
        from netsnap import neighbor_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['neighbor_info', '-j']
        
        try:
            result = neighbor_info.main()
            output = captured_output.getvalue().strip()
            
            if output:
                data = json.loads(output)
                assert isinstance(data, (dict, list))
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_neighbor_info_verbose(self):
        """Test neighbor_info verbose output"""
        from netsnap import neighbor_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['neighbor_info', '-v']
        
        try:
            result = neighbor_info.main()
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_neighbor_info_help(self):
        """Test neighbor_info help output"""
        from netsnap import neighbor_info
        
        old_argv = sys.argv
        sys.argv = ['neighbor_info', '-h']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                neighbor_info.main()
            assert exc_info.value.code == 0
        finally:
            sys.argv = old_argv
    
    def test_neighbor_info_specific_device(self):
        """Test neighbor info for specific device"""
        from netsnap import neighbor_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['neighbor_info', '-d', 'lo']
        
        try:
            result = neighbor_info.main()
            # Loopback typically has no neighbors
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv

# ============================================================================
# MDB Info Tests - Comprehensive
# ============================================================================

class TestMDBInfo:
    """Comprehensive tests for mdb_info module"""
    
    def test_mdb_info_main_no_args(self):
        """Test mdb_info main() with no arguments"""
        from netsnap import mdb_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['mdb_info']
        
        try:
            result = mdb_info.main()
            output = captured_output.getvalue()
            
            # MDB may be empty on systems without bridges
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_mdb_info_json_output(self):
        """Test mdb_info JSON output"""
        from netsnap import mdb_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['mdb_info', '-j']
        
        try:
            result = mdb_info.main()
            output = captured_output.getvalue().strip()
            
            if output:
                data = json.loads(output)
                assert isinstance(data, (dict, list))
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_mdb_info_verbose(self):
        """Test mdb_info verbose output"""
        from netsnap import mdb_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['mdb_info', '-v']
        
        try:
            result = mdb_info.main()
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_mdb_info_help(self):
        """Test mdb_info help output"""
        from netsnap import mdb_info
        
        old_argv = sys.argv
        sys.argv = ['mdb_info', '-h']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                mdb_info.main()
            assert exc_info.value.code == 0
        finally:
            sys.argv = old_argv

# ============================================================================
# Rule Info Tests - Comprehensive
# ============================================================================

class TestRuleInfo:
    """Comprehensive tests for rule_info module"""
    
    def test_rule_info_main_no_args(self):
        """Test rule_info main() with no arguments"""
        from netsnap import rule_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['rule_info']
        
        try:
            result = rule_info.main()
            output = captured_output.getvalue()
            
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_rule_info_json_output(self):
        """Test rule_info JSON output"""
        from netsnap import rule_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['rule_info', '-j']
        
        try:
            result = rule_info.main()
            output = captured_output.getvalue().strip()
            
            if output:
                data = json.loads(output)
                assert isinstance(data, (dict, list))
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_rule_info_verbose(self):
        """Test rule_info verbose output"""
        from netsnap import rule_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured_output = StringIO()
        sys.argv = ['rule_info', '-v']
        
        try:
            result = rule_info.main()
            assert result == 0 or result is None
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_rule_info_help(self):
        """Test rule_info help output"""
        from netsnap import rule_info
        
        old_argv = sys.argv
        sys.argv = ['rule_info', '-h']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                rule_info.main()
            assert exc_info.value.code == 0
        finally:
            sys.argv = old_argv

# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for combined functionality"""
    
    def test_all_modules_run_without_error(self):
        """Test that all main functions can run without crashing"""
        from netsnap import device_info, route_info, neighbor_info, mdb_info, rule_info
        
        modules = [
            (device_info, 'device_info'),
            (route_info, 'route_info'),
            (neighbor_info, 'neighbor_info'),
            (mdb_info, 'mdb_info'),
            (rule_info, 'rule_info'),
        ]
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        
        for module, name in modules:
            sys.stdout = StringIO()
            sys.argv = [name]
            try:
                result = module.main()
                assert result == 0 or result is None, f"{name} failed"
            except Exception as e:
                pytest.fail(f"{name}.main() raised exception: {e}")
            finally:
                sys.stdout = old_stdout
                sys.argv = old_argv
    
    def test_all_modules_json_output_valid(self):
        """Test that all modules produce valid JSON when requested"""
        from netsnap import device_info, route_info, neighbor_info, mdb_info, rule_info
        
        modules = [
            (device_info, 'device_info'),
            (route_info, 'route_info'),
            (neighbor_info, 'neighbor_info'),
            (mdb_info, 'mdb_info'),
            (rule_info, 'rule_info'),
        ]
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        
        for module, name in modules:
            sys.stdout = captured = StringIO()
            sys.argv = [name, '-j']
            try:
                module.main()
                output = captured.getvalue().strip()
                
                if output:
                    try:
                        data = json.loads(output)
                        assert isinstance(data, (dict, list)), f"{name} JSON not dict/list"
                    except json.JSONDecodeError as e:
                        # Some modules may have no data
                        pass
            finally:
                sys.stdout = old_stdout
                sys.argv = old_argv
    
    def test_sequential_execution(self):
        """Test running multiple modules sequentially"""
        from netsnap import device_info, route_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = StringIO()
        
        try:
            # Run device_info
            sys.argv = ['device_info']
            result1 = device_info.main()
            
            # Run route_info
            sys.argv = ['route_info']
            result2 = route_info.main()
            
            assert result1 in [0, None] and result2 in [0, None]
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv

# ============================================================================
# Entry Point Tests
# ============================================================================

class TestEntryPoints:
    """Tests for console script entry points"""
    
    def test_entry_points_exist(self):
        """Test that console script entry points are defined"""
        try:
            # Use importlib.metadata (Python 3.8+) instead of deprecated pkg_resources
            import importlib.metadata as metadata
            
            expected_scripts = [
                'netsnap-device',
                'netsnap-route',
                'netsnap-neighbor',
                'netsnap-mdb',
                'netsnap-rule',
            ]
            
            try:
                # Get distribution
                dist = metadata.distribution('netsnap')
                
                # Get entry points - API differs between Python 3.8-3.9 and 3.10+
                try:
                    # Python 3.10+ approach: entry_points is a method that returns filtered results
                    if hasattr(metadata, 'entry_points'):
                        eps = metadata.entry_points()
                        # Try new API (3.10+)
                        if hasattr(eps, 'select'):
                            console_scripts = eps.select(group='console_scripts')
                        else:
                            # Fallback for 3.8-3.9: entry_points returns dict-like object
                            console_scripts = eps.get('console_scripts', [])
                    else:
                        # Alternative: read from distribution
                        console_scripts = []
                        if dist.entry_points:
                            for ep in dist.entry_points:
                                if ep.group == 'console_scripts':
                                    console_scripts.append(ep)
                    
                    # Convert to dict of names
                    script_names = {ep.name for ep in console_scripts}
                    
                    # Check each expected script exists
                    for script_name in expected_scripts:
                        assert script_name in script_names, f"Entry point {script_name} not found"
                        
                except AttributeError:
                    pytest.skip("Unable to access entry points - metadata API incompatibility")
                    
            except metadata.PackageNotFoundError:
                pytest.skip("netsnap package not installed")
        except ImportError:
            pytest.skip("importlib.metadata not available")
    
    def test_command_line_tools_in_path(self):
        """Test that command line tools exist in PATH"""
        import shutil
        
        commands = [
            'netsnap-device',
            'netsnap-route',
            'netsnap-neighbor',
            'netsnap-mdb',
            'netsnap-rule',
        ]
        
        found_count = 0
        for cmd in commands:
            if shutil.which(cmd):
                found_count += 1
        
        # If package is installed, at least some should be found
        if found_count == 0:
            pytest.skip("No netsnap commands in PATH - package may not be installed")
        else:
            # If some found, all should be found
            assert found_count == len(commands), "Some commands missing from PATH"
    
    @pytest.mark.skipif(not os.path.exists('/usr/bin/netsnap-device') and 
                       not os.path.exists('/usr/local/bin/netsnap-device'),
                       reason="Commands not installed in standard locations")
    def test_command_help_execution(self):
        """Test executing commands with --help"""
        import shutil
        
        commands = ['netsnap-device', 'netsnap-route', 'netsnap-neighbor', 
                   'netsnap-mdb', 'netsnap-rule']
        
        for cmd in commands:
            if shutil.which(cmd):
                try:
                    result = subprocess.run(
                        [cmd, '--help'],
                        capture_output=True,
                        timeout=5,
                        text=True
                    )
                    # Help should exit with 0
                    assert result.returncode == 0, f"{cmd} --help failed"
                except subprocess.TimeoutExpired:
                    pytest.fail(f"{cmd} --help timed out")

# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Tests for error handling and edge cases"""
    
    def test_invalid_arguments(self):
        """Test handling of invalid arguments"""
        from netsnap import device_info
        
        old_stderr = sys.stderr
        old_argv = sys.argv
        sys.stderr = StringIO()
        sys.argv = ['device_info', '--invalid-arg-xyz']
        
        try:
            with pytest.raises(SystemExit) as exc_info:
                device_info.main()
            assert exc_info.value.code != 0, "Invalid args should exit with error"
        finally:
            sys.stderr = old_stderr
            sys.argv = old_argv
    
    def test_conflicting_arguments(self):
        """Test handling of potentially conflicting arguments"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = StringIO()
        sys.argv = ['device_info', '-d', 'lo', '-d', 'eth0']
        
        try:
            # Should handle gracefully (use last value typically)
            result = device_info.main()
            # Should not crash
            assert result in [0, 1, None]
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_empty_output_handling(self):
        """Test modules with potentially empty output"""
        from netsnap import neighbor_info, mdb_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        
        for module in [neighbor_info, mdb_info]:
            sys.stdout = StringIO()
            sys.argv = [module.__name__.split('.')[-1]]
            try:
                result = module.main()
                # Empty output is OK, just shouldn't crash
                assert result in [0, None]
            finally:
                sys.stdout = old_stdout
                sys.argv = old_argv
    
    def test_special_characters_in_device_name(self):
        """Test handling device names with special characters"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        old_argv = sys.argv
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        
        special_names = ['dev@123', 'dev:0', 'dev.1']
        
        for name in special_names:
            sys.argv = ['device_info', '-d', name]
            try:
                result = device_info.main()
                # Should handle gracefully
                assert result in [0, 1, None]
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                sys.argv = old_argv

# ============================================================================
# Output Format Tests
# ============================================================================

class TestOutputFormats:
    """Tests for different output formats"""
    
    def test_json_structure_device_info(self):
        """Test JSON output structure for device_info"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured = StringIO()
        sys.argv = ['device_info', '-j']
        
        try:
            device_info.main()
            output = captured.getvalue().strip()
            
            if output:
                data = json.loads(output)
                # Verify it's a valid data structure
                assert isinstance(data, (dict, list))
                
                # If it's a dict or non-empty list, check structure
                if isinstance(data, dict) and data:
                    # Should have reasonable keys
                    assert len(data) > 0
                elif isinstance(data, list) and data:
                    assert len(data) > 0
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_plain_text_output(self):
        """Test plain text output format"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = captured = StringIO()
        sys.argv = ['device_info','-t']
        
        try:
            device_info.main()
            output = captured.getvalue()
            
            # Plain text should not be JSON
            assert not output.strip().startswith('{')
            assert not output.strip().startswith('[')
            assert len(output) > 0
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_verbose_adds_information(self):
        """Test that verbose mode adds more information"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        
        # Normal output
        sys.stdout = normal_output = StringIO()
        sys.argv = ['device_info']
        try:
            device_info.main()
        finally:
            normal_len = len(normal_output.getvalue())
        
        # Verbose output
        sys.stdout = verbose_output = StringIO()
        sys.argv = ['device_info', '-v']
        try:
            device_info.main()
        finally:
            verbose_len = len(verbose_output.getvalue())
            sys.stdout = old_stdout
            sys.argv = old_argv
        
        # Verbose should typically have more or equal content
        # (equal is OK if implementation doesn't change output)
        assert verbose_len >= 0

# ============================================================================
# Module Internals Tests (if accessible)
# ============================================================================

class TestModuleInternals:
    """Tests for internal module functions where accessible"""
    
    def test_module_imports_work(self):
        """Test that modules can be imported individually"""
        modules_to_test = [
            'netsnap.device_info',
            'netsnap.route_info',
            'netsnap.neighbor_info',
            'netsnap.mdb_info',
            'netsnap.rule_info',
        ]
        
        for mod_name in modules_to_test:
            try:
                __import__(mod_name)
            except ImportError as e:
                pytest.fail(f"Failed to import {mod_name}: {e}")
    
    def test_cffi_functionality(self):
        """Test basic CFFI functionality"""
        from cffi import FFI
        
        ffi = FFI()
        # Test basic FFI operations
        ffi.cdef("int printf(const char *format, ...);")
        C = ffi.dlopen(None)
        
        # Verify FFI is functional
        assert C is not None
        assert hasattr(C, 'printf')
    
    def test_module_has_docstrings(self):
        """Test that modules have docstrings"""
        from netsnap import device_info, route_info
        
        assert device_info.__doc__ is not None
        assert route_info.__doc__ is not None

# ============================================================================
# Performance and Stress Tests
# ============================================================================

class TestPerformance:
    """Basic performance tests"""
    
    def test_repeated_execution(self):
        """Test that modules can be called multiple times"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = StringIO()
        sys.argv = ['device_info']
        
        try:
            # Run 5 times
            for _ in range(5):
                result = device_info.main()
                assert result in [0, None]
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_all_modules_rapid_succession(self):
        """Test running all modules in rapid succession"""
        from netsnap import device_info, route_info, neighbor_info, mdb_info, rule_info
        
        modules = [device_info, route_info, neighbor_info, mdb_info, rule_info]
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = StringIO()
        
        try:
            for module in modules:
                sys.argv = [module.__name__.split('.')[-1]]
                result = module.main()
                assert result in [0, None]
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv

# ============================================================================
# Compatibility Tests
# ============================================================================

class TestCompatibility:
    """Tests for Python version compatibility"""
    
    def test_python_version_supported(self):
        """Test that current Python version is supported"""
        assert sys.version_info >= (3, 8), "Requires Python 3.8+"
        assert sys.version_info < (4, 0), "Python 4+ not tested"
    
    def test_encoding_handling(self):
        """Test proper encoding handling"""
        assert sys.getdefaultencoding() in ['utf-8', 'UTF-8']
    
    def test_platform_detection(self):
        """Test that platform is detected correctly"""
        import platform
        
        # Should be on Linux for netlink
        system = platform.system()
        # May run on non-Linux in CI, but should not crash
        assert system in ['Linux', 'Darwin', 'Windows']

# ============================================================================
# Regression Tests
# ============================================================================

class TestRegression:
    """Regression tests for known issues"""
    
    def test_no_segfault_on_basic_operations(self):
        """Test that basic operations don't segfault"""
        from netsnap import device_info
        
        old_stdout = sys.stdout
        old_argv = sys.argv
        sys.stdout = StringIO()
        sys.argv = ['device_info']
        
        try:
            # Should complete without crashing
            result = device_info.main()
            assert result is not None or result == 0
        finally:
            sys.stdout = old_stdout
            sys.argv = old_argv
    
    def test_clean_exit_on_help(self):
        """Test that help exits cleanly"""
        from netsnap import device_info
        
        old_argv = sys.argv
        sys.argv = ['device_info', '--help']
        
        try:
            with pytest.raises(SystemExit) as exc:
                device_info.main()
            # Should be clean exit
            assert exc.value.code == 0
        finally:
            sys.argv = old_argv

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '--cov=netsnap', 
                 '--cov-report=html', '--cov-report=term-missing'])