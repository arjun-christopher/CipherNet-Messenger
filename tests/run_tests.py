#!/usr/bin/env python3
"""
Test Runner for CipherNet Messenger
Runs all test suites with coverage reporting.

Author: Arjun Christopher
"""

import sys
import subprocess
from pathlib import Path


def run_tests():
    """Run all tests with coverage reporting."""
    
    # Get project root (parent of tests folder)
    project_root = Path(__file__).parent.parent
    src_path = project_root / "src"
    tests_path = project_root / "tests"
    
    # Add src to Python path
    sys.path.insert(0, str(src_path))
    
    print("🔧 CipherNet Messenger - Test Suite")
    print("=" * 50)
    
    try:
        # Run pytest with coverage
        cmd = [
            sys.executable, "-m", "pytest",
            str(tests_path),
            "-v",  # Verbose output
            "--tb=short",  # Short traceback format
            "--color=yes",  # Colored output
            f"--rootdir={project_root}",
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        print("-" * 50)
        
        result = subprocess.run(cmd, cwd=project_root)
        
        print("-" * 50)
        if result.returncode == 0:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed!")
            
        return result.returncode
        
    except FileNotFoundError:
        print("❌ pytest not found. Please install it:")
        print("pip install pytest pytest-mock")
        return 1
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return 1


def run_specific_test(test_file):
    """
    Run a specific test file.
    
    Args:
        test_file: Name of the test file to run
    """
    project_root = Path(__file__).parent.parent
    tests_path = project_root / "tests" / test_file
    
    if not tests_path.exists():
        print(f"❌ Test file not found: {test_file}")
        return 1
    
    cmd = [
        sys.executable, "-m", "pytest",
        str(tests_path),
        "-v",
        "--tb=short",
        "--color=yes"
    ]
    
    print(f"Running {test_file}...")
    print("-" * 30)
    
    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Run specific test file
        test_file = sys.argv[1]
        if not test_file.startswith("test_"):
            test_file = f"test_{test_file}"
        if not test_file.endswith(".py"):
            test_file = f"{test_file}.py"
        
        exit_code = run_specific_test(test_file)
    else:
        # Run all tests
        exit_code = run_tests()
    
    sys.exit(exit_code)