# OSS-Fuzz Integration Guide for pqc-combo

## 🎯 What is OSS-Fuzz?

OSS-Fuzz is Google's continuous fuzzing service for open source projects. It provides:

- **24/7 Fuzzing**: Runs your fuzzers continuously on Google's infrastructure
- **ClusterFuzz**: Advanced corpus management and mutation strategies
- **Multiple Sanitizers**: ASan, MSan, UBSan, CFI
- **Coverage-Guided**: Intelligent input generation using coverage feedback
- **Automatic Bug Reports**: Creates GitHub issues when bugs are found
- **Free Service**: No cost for open source projects

## 📋 Prerequisites

- Open source project hosted on GitHub
- Project maintained and actively developed
- Willingness to fix bugs found by fuzzing

## 🚀 Quick Start

### 1. Local Testing (Before Submission)

Test your fuzzing setup locally using OSS-Fuzz's helper scripts:

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Create project directory
mkdir projects/pqc-combo

# Copy configuration files
cp /path/to/pqc-combo/oss-fuzz/* projects/pqc-combo/

# Build Docker image
python infra/helper.py build_image pqc-combo

# Build fuzzers
python infra/helper.py build_fuzzers pqc-combo

# Run a fuzzer
python infra/helper.py run_fuzzer pqc-combo fuzz_kyber_keys -- -max_total_time=60

# Check build
python infra/helper.py check_build pqc-combo
```

### 2. Submit to OSS-Fuzz

Once local testing passes:

```bash
# Fork OSS-Fuzz on GitHub
# Add your project files to projects/pqc-combo/
# Submit a PR to google/oss-fuzz

# PR should include:
# - projects/pqc-combo/project.yaml
# - projects/pqc-combo/Dockerfile  
# - projects/pqc-combo/build.sh
```

## 📁 Required Files

### project.yaml

Configuration file for your project:

```yaml
homepage: "https://www.pqc-combo.com"
language: rust
primary_contact: "aaronschnacky@gmail.com"
auto_ccs:
  - "security@pqc-combo.com"

sanitizers:
  - address
  - undefined
  - memory

main_repo: "https://github.com/AaronSchnacky1/pqc-combo.git"
```

**Key Fields:**
- `homepage`: Your project website
- `primary_contact`: Email for bug reports (must be responsive!)
- `auto_ccs`: Additional email addresses for notifications
- `sanitizers`: Which sanitizers to use
- `main_repo`: Git repository URL

### Dockerfile

Defines the build environment:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-rust

# Install any additional dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config

# Clone repository
RUN git clone --depth 1 https://github.com/AaronSchnacky1/pqc-combo.git pqc-combo

WORKDIR $SRC/pqc-combo

# Copy build script
COPY build.sh $SRC/
```

**Important:**
- Must use `gcr.io/oss-fuzz-base/base-builder-rust` as base
- Clone into `$SRC/pqc-combo`
- Copy build.sh to `$SRC/`

### build.sh

Builds your fuzz targets:

```bash
#!/bin/bash -eu

cd $SRC/pqc-combo

# Build all fuzz targets
cargo fuzz build --release

# Copy to output directory
FUZZ_TARGETS=(
    "fuzz_kyber_keys"
    "fuzz_dilithium_keys"
    "fuzz_encapsulation"
    "fuzz_signature"
    "fuzz_kyber_structured"
    "fuzz_dilithium_structured"
    "fuzz_pct"
    "fuzz_state_machine"
    "fuzz_aes_gcm"
)

for target in "${FUZZ_TARGETS[@]}"; do
    cp target/x86_64-unknown-linux-gnu/release/$target $OUT/
done
```

**Key Points:**
- Must be executable: `chmod +x build.sh`
- Use `$OUT` for output directory
- Use `$SRC` for source directory
- Exit on error: `#!/bin/bash -eu`

## 🔧 Advanced Configuration

### Seed Corpus

Provide initial test cases for better coverage:

```bash
# In build.sh, create seed corpus directories
mkdir -p $OUT/fuzz_kyber_keys_seed_corpus

# Add seed files
echo "seed1_content" > $OUT/fuzz_kyber_keys_seed_corpus/seed1.bin
echo "seed2_content" > $OUT/fuzz_kyber_keys_seed_corpus/seed2.bin
```

### Dictionaries

Help fuzzer generate better inputs:

```bash
# Create dictionary file
cat > $OUT/fuzz_kyber_keys.dict <<EOF
# Common values
"\x00\x01\x02\x03"
"\xFF\xFF\xFF\xFF"
# Add more patterns
EOF
```

### Fuzzing Options

Configure fuzzer behavior in `$OUT/fuzz_target.options`:

```bash
cat > $OUT/fuzz_kyber_keys.options <<EOF
[libfuzzer]
max_len = 10000
timeout = 25
```

### Multiple Sanitizers

Build with different sanitizers:

```bash
# In build.sh
case $SANITIZER in
    address)
        RUSTFLAGS="$RUSTFLAGS -Zsanitizer=address"
        ;;
    memory)
        RUSTFLAGS="$RUSTFLAGS -Zsanitizer=memory"
        ;;
    undefined)
        RUSTFLAGS="$RUSTFLAGS -Zsanitizer=undefined"
        ;;
esac
```

## 🧪 Local Testing Commands

### Build and Test

```bash
# Full build and test cycle
python infra/helper.py build_image pqc-combo
python infra/helper.py build_fuzzers pqc-combo
python infra/helper.py run_fuzzer pqc-combo fuzz_kyber_keys

# Test specific sanitizer
python infra/helper.py build_fuzzers --sanitizer=memory pqc-combo
python infra/helper.py run_fuzzer --sanitizer=memory pqc-combo fuzz_kyber_keys

# Check for errors
python infra/helper.py check_build pqc-combo

# Generate coverage report
python infra/helper.py coverage pqc-combo
```

### Debugging

```bash
# Run with shell access
python infra/helper.py shell pqc-combo

# Inside container
cd /src/pqc-combo
cargo fuzz run fuzz_kyber_keys

# Reproduce crash
python infra/helper.py reproduce pqc-combo fuzz_kyber_keys crash-file
```

## 📊 After Integration

### Monitoring

Once accepted, you'll receive:

1. **Bug Reports**: Automatically filed as GitHub issues
2. **Coverage Reports**: Weekly coverage statistics
3. **Build Status**: Notifications if builds fail

### Dashboard

View your project status:
- https://oss-fuzz.com/pqc-combo
- Coverage: https://oss-fuzz.com/coverage-report/job/libfuzzer_asan_pqc-combo/latest

### Build Logs

Check build status:
- https://oss-fuzz-build-logs.storage.googleapis.com/index.html#pqc-combo

## 🐛 Handling Bug Reports

When OSS-Fuzz finds a bug:

1. **Issue Created**: Automatically on your GitHub repo
2. **Severity Labels**: Based on sanitizer findings
3. **Reproducers Provided**: Crash-triggering inputs attached
4. **Private Initially**: Disclosed after 90 days or fix

### Response Process

```bash
# 1. Download reproducer from GitHub issue
wget https://github.com/.../crash-abc123

# 2. Reproduce locally
cargo fuzz run fuzz_kyber_keys crash-abc123

# 3. Debug with backtrace
RUST_BACKTRACE=full cargo fuzz run fuzz_kyber_keys crash-abc123

# 4. Fix the bug
# ... make changes ...

# 5. Verify fix
cargo fuzz run fuzz_kyber_keys crash-abc123

# 6. Run regression test
cargo test

# 7. Update issue with fix
# Comment on GitHub issue with commit SHA
```

## 🔐 Security Considerations

### Disclosure Policy

OSS-Fuzz follows a **90-day disclosure timeline**:

1. **Day 0**: Bug found, private issue created
2. **Day 7**: First reminder if not fixed
3. **Day 14**: Second reminder
4. **Day 30**: Third reminder
5. **Day 90**: Public disclosure (or earlier if fixed)

### Handling Sensitive Bugs

For critical security issues:

1. **Request extended deadline**: Comment on issue
2. **Provide update timeline**: Show progress
3. **Fix quickly**: Aim for <30 days
4. **Coordinate disclosure**: Work with OSS-Fuzz team

## 📈 Optimization Tips

### Improve Fuzzing Efficiency

1. **Better Seed Corpus**:
   ```bash
   # Include real-world test vectors
   # Include edge cases
   # Include various input sizes
   ```

2. **Faster Fuzz Targets**:
   ```rust
   // Avoid expensive operations in inner loop
   // Use --release builds
   // Minimize allocations
   ```

3. **Better Coverage**:
   ```rust
   // Ensure all code paths are reachable
   // Remove dead code
   // Add instrumentation
   ```

### Memory Usage

Keep memory usage reasonable:

```bash
# In .options file
[libfuzzer]
rss_limit_mb = 2048  # Limit to 2GB
```

## 📞 Support

### OSS-Fuzz Community

- **Mailing List**: oss-fuzz@googlegroups.com
- **GitHub**: https://github.com/google/oss-fuzz/issues
- **Documentation**: https://google.github.io/oss-fuzz/

### Project-Specific

- **GitHub Issues**: https://github.com/AaronSchnacky1/pqc-combo/issues
- **Email**: aaronschnacky@gmail.com
- **Security**: security@pqc-combo.com

## ✅ Pre-Submission Checklist

Before submitting to OSS-Fuzz:

- [ ] All fuzzers build successfully locally
- [ ] Fuzzers run without crashes for 5+ minutes
- [ ] `check_build` passes
- [ ] project.yaml is complete and accurate
- [ ] Primary contact email is valid and monitored
- [ ] Repository is public and maintained
- [ ] License is open source compatible
- [ ] README mentions fuzzing support

## 🎯 Expected Timeline

- **Submission**: PR to google/oss-fuzz
- **Review**: 1-2 weeks for initial review
- **Integration**: 1-2 days after approval
- **First Run**: Within 24 hours of integration
- **First Bug Report**: Varies (could be hours to weeks)

## 📚 Additional Resources

- **OSS-Fuzz Documentation**: https://google.github.io/oss-fuzz/
- **Fuzzing Best Practices**: https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/
- **Rust Fuzzing Book**: https://rust-fuzz.github.io/book/
- **ClusterFuzz**: https://google.github.io/clusterfuzz/

## 🎉 Success Metrics

After integration, track:

- **Coverage**: Target >80% code coverage
- **Corpus Size**: Growing corpus indicates good fuzzing
- **Executions/Second**: Higher is better
- **Bugs Found**: Shows effectiveness (though 0 is also good!)
- **Build Health**: Should stay green

---

**Example Successful Projects:**

- **rustls**: TLS library, found multiple bugs
- **ring**: Crypto library, continuous coverage improvements
- **image-rs**: Image processing, high coverage achieved

**pqc-combo aims to join this list of well-fuzzed Rust crypto projects!**

---

**Last Updated**: November 2024  
**Maintainer**: Aaron Schnacky (aaronschnacky@gmail.com)  
**Status**: Ready for OSS-Fuzz submission
