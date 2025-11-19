#!/bin/bash
# pqc-combo Testing Script
# Runs comprehensive test suite with various configurations

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}âœ" $1${NC}"
}

print_error() {
    echo -e "${RED}âœ— $1${NC}"
}

print_info() {
    echo -e "${YELLOW}â„¹ $1${NC}"
}

# Track results
FAILED=0
PASSED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}Running: $test_name${NC}"
    if eval "$test_command"; then
        print_success "$test_name passed"
        ((PASSED++))
    else
        print_error "$test_name failed"
        ((FAILED++))
    fi
}

# Parse arguments
QUICK=false
FUZZ_TIME=60
COVERAGE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK=true
            shift
            ;;
        --fuzz-time)
            FUZZ_TIME="$2"
            shift 2
            ;;
        --coverage)
            COVERAGE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick         Run quick tests only (skip fuzzing and extended tests)"
            echo "  --fuzz-time N   Set fuzzing time per target in seconds (default: 60)"
            echo "  --coverage      Generate coverage report"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

print_header "pqc-combo Comprehensive Test Suite"

# 1. Basic Unit Tests
print_header "1. Unit Tests"
run_test "Unit tests (default features)" "cargo test --lib"
run_test "Unit tests (all features)" "cargo test --lib --all-features"

# 2. Integration Tests
print_header "2. Integration Tests"
run_test "Integration tests" "cargo test --test integration --features 'std,ml-kem,ml-dsa'"
run_test "CAST tests" "cargo test --test cast_tests --features std"
run_test "FIPS 140-3 tests" "cargo test --test fips_140_3 --features 'std,fips_140_3'"

# 3. Property-Based Tests
print_header "3. Property-Based Tests"
run_test "Property tests (100 cases)" "PROPTEST_CASES=100 cargo test --test property_tests --features 'std,ml-kem,ml-dsa'"

if [ "$QUICK" = false ]; then
    run_test "Property tests (1000 cases)" "PROPTEST_CASES=1000 cargo test --test property_tests --features 'std,ml-kem,ml-dsa'"
fi

# 4. Cross-Validation Tests
print_header "4. Cross-Implementation Validation"
run_test "Cross-validation tests" "cargo test --test cross_validation --features 'std,ml-kem,ml-dsa'"

# 5. Feature Combination Tests
print_header "5. Feature Combination Tests"
run_test "ML-KEM only" "cargo test --no-default-features --features 'ml-kem,std'"
run_test "ML-DSA only" "cargo test --no-default-features --features 'ml-dsa,std'"
run_test "no_std (no_alloc)" "cargo build --no-default-features --features 'ml-kem,ml-dsa'"
run_test "no_std (with alloc)" "cargo build --no-default-features --features 'alloc,ml-kem,ml-dsa'"
run_test "With AES-GCM" "cargo test --features 'std,ml-kem,ml-dsa,aes-gcm'"

# 6. Benchmarks
print_header "6. Benchmarks"
if [ "$QUICK" = false ]; then
    run_test "Benchmark compilation" "cargo bench --no-run"
    print_info "Run 'cargo bench' separately for full benchmark results"
else
    print_info "Skipping benchmarks (use without --quick to run)"
fi

# 7. Fuzzing (if cargo-fuzz is installed)
if command -v cargo-fuzz &> /dev/null; then
    if [ "$QUICK" = false ]; then
        print_header "7. Fuzzing Tests"
        
        FUZZ_TARGETS=(
            "fuzz_kyber_keys"
            "fuzz_dilithium_keys"
            "fuzz_encapsulation"
            "fuzz_signature"
        )
        
        for target in "${FUZZ_TARGETS[@]}"; do
            run_test "Fuzzing: $target" "cargo fuzz run $target -- -max_total_time=$FUZZ_TIME -runs=0"
        done
    else
        print_info "Skipping fuzzing (use without --quick to run)"
    fi
else
    print_info "cargo-fuzz not installed, skipping fuzzing tests"
    print_info "Install with: cargo install cargo-fuzz"
fi

# 8. Code Coverage (if requested)
if [ "$COVERAGE" = true ]; then
    print_header "8. Code Coverage"
    
    if command -v cargo-tarpaulin &> /dev/null; then
        run_test "Coverage generation" "cargo tarpaulin --all-features --out Html --output-dir coverage"
        print_success "Coverage report generated in coverage/index.html"
    else
        print_error "cargo-tarpaulin not installed"
        print_info "Install with: cargo install cargo-tarpaulin"
    fi
fi

# 9. Documentation Tests
print_header "9. Documentation Tests"
run_test "Doc tests" "cargo test --doc --all-features"

# 10. Clippy Lints
print_header "10. Clippy Lints"
run_test "Clippy" "cargo clippy --all-features -- -D warnings"

# Summary
print_header "Test Summary"

TOTAL=$((PASSED + FAILED))

echo ""
echo "Total tests: $TOTAL"
print_success "Passed: $PASSED"

if [ $FAILED -gt 0 ]; then
    print_error "Failed: $FAILED"
    echo ""
    print_error "Some tests failed. Please review the output above."
    exit 1
else
    echo ""
    print_success "All tests passed! 🎉"
    
    if [ "$QUICK" = true ]; then
        echo ""
        print_info "Quick mode was used. Run without --quick for comprehensive testing."
    fi
    
    if [ "$COVERAGE" = false ]; then
        echo ""
        print_info "Run with --coverage to generate coverage report."
    fi
    
    exit 0
fi
